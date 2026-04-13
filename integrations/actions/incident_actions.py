from __future__ import annotations

import hashlib
import ipaddress
import re
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from html import unescape
from typing import Any, Dict
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.utils.dateparse import parse_datetime

from audit.utils import log_action
from incidents.custom_fields import (
    CustomFieldPayloadError,
    get_custom_field_definition_map,
    reconcile_custom_field_values,
    validate_custom_field_input,
)
from incidents.models import Artifact, CustomFieldDefinition, IncidentTask, TimelineEntry
from incidents.services import (
    add_artifact_link,
    create_communication,
    create_artifact_record,
    create_task,
    escalate_incident,
    update_artifact,
    update_artifact_attributes,
    update_artifact_hash,
    update_incident_assignee,
    update_incident_impact,
    update_incident_labels,
    update_incident_status,
    update_task,
)

from ..registry import register

User = get_user_model()

URL_PATTERN = re.compile(r"https?://[^\s<>'\"`]+", re.IGNORECASE)
HREF_PATTERN = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _require_incident(context: Dict[str, Any]):
    incident = context.get("incident")
    if incident is None:
        raise ValueError("Contexto sem incidente")
    return incident


def _resolve_user(identifier):
    if not identifier:
        return None
    if isinstance(identifier, User):
        return identifier
    try:
        return User.objects.get(pk=int(identifier))
    except (User.DoesNotExist, ValueError, TypeError):
        try:
            return User.objects.get(username=str(identifier))
        except User.DoesNotExist:
            raise ValueError(f"Usuario '{identifier}' nao encontrado")


def _normalize_custom_field_internal_id(raw_value) -> str | None:
    if isinstance(raw_value, bool):
        return None
    if isinstance(raw_value, int):
        return str(raw_value) if raw_value > 0 else None
    if isinstance(raw_value, str):
        candidate = raw_value.strip()
        if candidate.isdigit() and int(candidate) > 0:
            return str(int(candidate))
    return None


def _resolve_custom_field_internal_id(*, internal_id=None, api_name=None) -> str:
    definitions = get_custom_field_definition_map(include_inactive=True)
    if api_name:
        normalized_api_name = CustomFieldDefinition.normalize_api_name(str(api_name))
        if not normalized_api_name:
            raise ValueError("api_name de custom field invalido.")
        for key, definition in definitions.items():
            if definition.api_name != normalized_api_name:
                continue
            if not definition.is_active:
                raise ValueError(f"Campo customizado '{normalized_api_name}' esta inativo.")
            return key
        raise ValueError(f"Campo customizado '{normalized_api_name}' nao encontrado.")

    normalized_internal_id = _normalize_custom_field_internal_id(internal_id)
    if normalized_internal_id is None:
        raise ValueError("Informe internal_id ou api_name para o custom field.")
    definition = definitions.get(normalized_internal_id)
    if definition is None:
        raise ValueError(f"Campo customizado '{normalized_internal_id}' nao encontrado.")
    if not definition.is_active:
        raise ValueError(f"Campo customizado '{normalized_internal_id}' esta inativo.")
    return normalized_internal_id


def _resolve_artifact(*, incident, context: Dict[str, Any], artifact_id=None) -> Artifact:
    if artifact_id:
        try:
            return incident.artifacts.get(pk=artifact_id)
        except incident.artifacts.model.DoesNotExist:
            raise ValueError("Artefato nao encontrado no incidente")
    artifact = context.get("artifact_instance")
    if artifact is None:
        raise ValueError("Nenhum artefato disponivel no contexto")
    if not incident.artifacts.filter(pk=artifact.pk).exists():
        raise ValueError("Artefato do contexto nao pertence ao incidente")
    return artifact


def _decoded_header(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _dedupe_strings(values):
    seen = set()
    ordered = []
    for value in values:
        normalized = (value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _normalize_raw_message(raw_message: Any) -> str:
    if raw_message is None:
        raise ValueError("raw_message obrigatorio")
    if isinstance(raw_message, bytes):
        return raw_message.decode("utf-8", errors="replace")
    return str(raw_message)


def _parse_email_message(raw_message: Any):
    raw_text = _normalize_raw_message(raw_message)
    return BytesParser(policy=policy.default).parsebytes(raw_text.encode("utf-8", errors="replace")), raw_text


def _read_raw_message_from_artifact(artifact: Artifact) -> str | None:
    attributes = artifact.attributes or {}
    raw_message = attributes.get("email_raw") or attributes.get("raw_message")
    if raw_message:
        return _normalize_raw_message(raw_message)
    if artifact.file:
        artifact.file.open("rb")
        try:
            content = artifact.file.read()
        finally:
            artifact.file.close()
        return _normalize_raw_message(content)
    if artifact.type == Artifact.Type.EMAIL and ("\n" in (artifact.value or "") or "\r" in (artifact.value or "")):
        return artifact.value
    return None


def _resolve_email_source(*, step, context: Dict[str, Any], incident):
    if step.input.get("raw_message") is not None:
        message, raw_text = _parse_email_message(step.input.get("raw_message"))
        return message, raw_text, None
    artifact = _resolve_artifact(
        incident=incident,
        context=context,
        artifact_id=step.input.get("artifact_id"),
    )
    raw_message = _read_raw_message_from_artifact(artifact)
    if raw_message is None:
        raise ValueError("Email bruto nao disponivel no artefato")
    message, raw_text = _parse_email_message(raw_message)
    return message, raw_text, artifact


def _extract_header_addresses(message, header_name: str) -> list[str]:
    return _dedupe_strings(addr.lower() for _, addr in getaddresses(message.get_all(header_name, [])) if addr)


def _extract_auth_results(message) -> dict[str, dict[str, Any]]:
    authentication_results = " ".join(_decoded_header(value) for value in message.get_all("Authentication-Results", []))
    received_spf = " ".join(_decoded_header(value) for value in message.get_all("Received-SPF", []))
    auth = {
        "spf": {"result": None},
        "dkim": {"result": None},
        "dmarc": {"result": None},
    }
    for mechanism, result in AUTH_RESULT_PATTERN.findall(authentication_results):
        auth[mechanism.lower()]["result"] = result.lower()
    if auth["spf"]["result"] is None and received_spf:
        lowered = received_spf.lower()
        for candidate in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
            if candidate in lowered:
                auth["spf"]["result"] = candidate
                break
    auth["spf"]["source_header"] = received_spf or authentication_results or ""
    auth["dkim"]["present"] = bool(message.get("DKIM-Signature"))
    auth["dmarc"]["source_header"] = authentication_results or ""
    return auth


def _extract_basic_email_headers(message) -> dict[str, Any]:
    return {
        "from": _decoded_header(message.get("From")),
        "from_addresses": _extract_header_addresses(message, "From"),
        "reply_to": _decoded_header(message.get("Reply-To")),
        "reply_to_addresses": _extract_header_addresses(message, "Reply-To"),
        "to": _dedupe_strings(_decoded_header(value) for value in message.get_all("To", [])),
        "to_addresses": _extract_header_addresses(message, "To"),
        "cc": _dedupe_strings(_decoded_header(value) for value in message.get_all("Cc", [])),
        "cc_addresses": _extract_header_addresses(message, "Cc"),
        "subject": _decoded_header(message.get("Subject")),
        "message_id": _decoded_header(message.get("Message-ID")),
        "date": _decoded_header(message.get("Date")),
        "received": _dedupe_strings(_decoded_header(value) for value in message.get_all("Received", [])),
        "authentication": _extract_auth_results(message),
    }


def _extract_email_bodies(message) -> tuple[list[str], list[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    parts = list(message.walk()) if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace")
        if isinstance(content, bytes):
            charset = part.get_content_charset() or "utf-8"
            content = content.decode(charset, errors="replace")
        if not isinstance(content, str):
            content = str(content)
        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)
    return plain_parts, html_parts


def _clean_url(url: str) -> str:
    cleaned = unescape((url or "").strip())
    return cleaned.rstrip(").,;]>\"'")


def _extract_links_from_message(message) -> list[str]:
    plain_parts, html_parts = _extract_email_bodies(message)
    links: list[str] = []
    for part in plain_parts:
        links.extend(_clean_url(match.group(0)) for match in URL_PATTERN.finditer(part))
    for html in html_parts:
        links.extend(_clean_url(match.group(1)) for match in HREF_PATTERN.finditer(html))
        links.extend(_clean_url(match.group(0)) for match in URL_PATTERN.finditer(html))
    return _dedupe_strings(links)


def _extract_attachment_metadata(message) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for part in message.iter_attachments():
        payload = part.get_payload(decode=True) or b""
        filename = _decoded_header(part.get_filename())
        attachments.append(
            {
                "filename": filename,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            }
        )
    return attachments


def _extract_domain_candidates(message, links: list[str], headers: dict[str, Any]) -> list[str]:
    domains: list[str] = []
    for url in links:
        hostname = (urlparse(url).hostname or "").lower()
        if hostname:
            domains.append(hostname)
    for address in (
        headers.get("from_addresses", [])
        + headers.get("reply_to_addresses", [])
        + headers.get("to_addresses", [])
        + headers.get("cc_addresses", [])
    ):
        if "@" in address:
            domains.append(address.split("@", 1)[1].lower())
    return _dedupe_strings(domains)


def _extract_ip_candidates(message, links: list[str], headers: dict[str, Any]) -> list[str]:
    ips: list[str] = []
    for url in links:
        hostname = (urlparse(url).hostname or "").strip()
        if not hostname:
            continue
        try:
            ips.append(str(ipaddress.ip_address(hostname)))
        except ValueError:
            continue
    for received_value in headers.get("received", []):
        for match in IPV4_PATTERN.findall(received_value):
            try:
                ips.append(str(ipaddress.ip_address(match)))
            except ValueError:
                continue
    return _dedupe_strings(ips)


def _persist_artifact_attributes(*, artifact: Artifact | None, incident, actor, attributes: dict[str, Any], context):
    if artifact is None:
        return
    update_artifact_attributes(
        artifact=artifact,
        incident=incident,
        attributes=attributes,
        merge=True,
        actor=actor,
    )
    artifact.refresh_from_db(fields=["attributes"])
    context.setdefault("artifact", {})["attributes"] = artifact.attributes


def _email_artifact_value(headers: dict[str, Any]) -> str:
    for candidate in (
        headers.get("message_id"),
        headers.get("subject"),
        headers.get("from_addresses", [None])[0],
        headers.get("from"),
    ):
        normalized = (candidate or "").strip()
        if normalized:
            return normalized[:512]
    return "email-raw"


@register("incident.add_label")
def add_label(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    label = step.input.get("label")
    if not label:
        raise ValueError("Label obrigatorio")
    actor = context.get("actor")
    incident.add_label(label, actor=actor)
    return {"label": label, "labels": incident.labels}


@register("incident.add_labels")
def add_labels(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    labels = step.input.get("labels") or []
    if not isinstance(labels, (list, tuple)):
        raise ValueError("labels deve ser uma lista")
    actor = context.get("actor")
    update_incident_labels(incident=incident, add=list(labels), actor=actor)
    return {"labels": incident.labels}


@register("incident.add_note")
def add_note(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message = step.input.get("message")
    if not message:
        raise ValueError("Mensagem obrigatoria")
    entry_type = step.input.get("entry_type", TimelineEntry.EntryType.NOTE)
    meta = step.input.get("meta", {})
    actor = context.get("actor")
    incident.log_timeline(entry_type=entry_type, message=message, actor=actor, extra=meta)
    return {"message": message, "entry_type": entry_type, "meta": meta}


@register("incident.update_status")
def update_status(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    status = step.input.get("status")
    if not status:
        raise ValueError("Status obrigatorio")
    reason = step.input.get("reason")
    actor = context.get("actor")
    result = update_incident_status(incident=incident, status=status, reason=reason, actor=actor)
    return {"status": incident.status, "changed": result.changed, "reason": reason}


@register("incident.assign")
def assign_incident(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    identifier = step.input.get("assignee") or step.input.get("assignee_id")
    assignee = _resolve_user(identifier) if identifier else None
    actor = context.get("actor")
    result = update_incident_assignee(incident=incident, assignee=assignee, actor=actor)
    return {
        "assignee": getattr(assignee, "username", None),
        "changed": result.changed,
    }


@register("incident.update_impact")
def update_impact(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    data = {
        "impact_systems": step.input.get("impact_systems"),
        "risk_score": step.input.get("risk_score"),
        "severity": step.input.get("severity"),
        "estimated_cost": step.input.get("estimated_cost"),
        "business_unit": step.input.get("business_unit"),
        "data_classification": step.input.get("data_classification"),
    }
    actor = context.get("actor")
    result = update_incident_impact(incident=incident, actor=actor, **data)
    payload = {
        "impact_systems": incident.impact_systems,
        "risk_score": incident.risk_score,
        "severity": incident.severity,
        "estimated_cost": incident.estimated_cost,
        "business_unit": incident.business_unit,
        "data_classification": incident.data_classification,
        "changed": result.changed,
    }
    return payload


@register("incident.custom_fields.set")
def set_incident_custom_field(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    actor = context.get("actor")
    internal_id = _resolve_custom_field_internal_id(
        internal_id=step.input.get("internal_id"),
        api_name=step.input.get("api_name"),
    )
    definition_map = get_custom_field_definition_map(include_inactive=True)
    try:
        validated_payload = validate_custom_field_input(
            {internal_id: step.input.get("value")},
            definition_map=definition_map,
            active_only=True,
        )
    except CustomFieldPayloadError as exc:
        raise ValueError(
            "; ".join(f"{key}: {message}" for key, message in exc.errors.items())
        ) from exc

    current_values, reconciled_changed = reconcile_custom_field_values(
        incident.custom_fields or {},
        definition_map=definition_map,
    )
    updated_values = dict(current_values)
    updated_values.update(validated_payload)
    changed = reconciled_changed or updated_values != current_values
    if changed:
        incident.custom_fields = updated_values
        incident._save_with_skip_signals(update_fields=["custom_fields", "updated_at"])
        definition = definition_map.get(internal_id)
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message=(
                f"Campo customizado '{definition.display_name if definition else internal_id}' "
                "atualizado via playbook"
            ),
            actor=actor,
            extra={"custom_field_ids": [internal_id], "source": "playbook"},
        )
        log_action(
            actor=actor,
            verb="incident.custom_fields_updated_via_playbook",
            target=incident,
            meta={"custom_field_ids": [internal_id]},
        )

    definition = definition_map.get(internal_id)
    return {
        "changed": changed,
        "internal_id": internal_id,
        "api_name": getattr(definition, "api_name", None),
        "value": (incident.custom_fields or {}).get(internal_id),
    }


@register("incident.custom_fields.merge")
def merge_incident_custom_fields(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    actor = context.get("actor")
    raw_fields = step.input.get("fields")
    if not isinstance(raw_fields, dict) or not raw_fields:
        raise ValueError("Campo 'fields' deve ser um objeto JSON nao vazio.")

    definition_map = get_custom_field_definition_map(include_inactive=True)
    normalized_payload: dict[str, Any] = {}
    for raw_key, value in raw_fields.items():
        normalized_payload[
            _resolve_custom_field_internal_id(internal_id=raw_key, api_name=raw_key)
            if not _normalize_custom_field_internal_id(raw_key)
            else _resolve_custom_field_internal_id(internal_id=raw_key)
        ] = value

    try:
        validated_payload = validate_custom_field_input(
            normalized_payload,
            definition_map=definition_map,
            active_only=True,
        )
    except CustomFieldPayloadError as exc:
        raise ValueError(
            "; ".join(f"{key}: {message}" for key, message in exc.errors.items())
        ) from exc

    current_values, reconciled_changed = reconcile_custom_field_values(
        incident.custom_fields or {},
        definition_map=definition_map,
    )
    updated_values = dict(current_values)
    updated_values.update(validated_payload)
    changed = reconciled_changed or updated_values != current_values
    if changed:
        incident.custom_fields = updated_values
        incident._save_with_skip_signals(update_fields=["custom_fields", "updated_at"])
        incident.log_timeline(
            entry_type=TimelineEntry.EntryType.NOTE,
            message="Campos customizados atualizados via playbook",
            actor=actor,
            extra={"custom_field_ids": sorted(validated_payload.keys()), "source": "playbook"},
        )
        log_action(
            actor=actor,
            verb="incident.custom_fields_updated_via_playbook",
            target=incident,
            meta={"custom_field_ids": sorted(validated_payload.keys())},
        )

    by_api_name: dict[str, Any] = {}
    for field_id, value in validated_payload.items():
        definition = definition_map.get(field_id)
        if definition and definition.api_name:
            by_api_name[definition.api_name] = value

    return {
        "changed": changed,
        "updated_internal_ids": sorted(validated_payload.keys()),
        "updated_api_names": sorted(by_api_name.keys()),
        "values_by_api_name": by_api_name,
    }


@register("incident.escalate")
def escalate(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    level = step.input.get("level")
    targets = step.input.get("targets") or []
    if level is None and not targets:
        raise ValueError("Informe level ou targets")
    actor = context.get("actor")
    result = escalate_incident(incident=incident, level=level, targets=targets, actor=actor)
    return {
        "level": incident.escalation_level,
        "targets": incident.escalation_targets,
        "changed": result.changed,
    }


@register("incident.log_action")
def log_audit_action(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    verb = step.input.get("verb")
    if not verb:
        raise ValueError("Verbo obrigatorio")
    meta = step.input.get("meta", {})
    actor = context.get("actor")
    entry = log_action(actor=actor, verb=verb, target=incident, meta=meta)
    return {"verb": entry.verb, "meta": entry.meta}


@register("task.create")
def create_followup_task(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    title = step.input.get("title")
    if not title:
        raise ValueError("Titulo obrigatorio")
    owner_identifier = step.input.get("owner") or step.input.get("owner_id")
    owner = _resolve_user(owner_identifier) if owner_identifier else None
    eta_raw = step.input.get("eta")
    eta = parse_datetime(eta_raw) if eta_raw else None
    actor = context.get("actor")
    task = create_task(incident=incident, title=title, owner=owner, eta=eta, actor=actor)
    return {
        "task_id": task.id,
        "title": task.title,
        "owner": getattr(task.owner, "username", None),
        "eta": task.eta.isoformat() if task.eta else None,
    }


@register("task.complete")
def complete_task(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    task_id = step.input.get("task_id")
    title = step.input.get("title")
    if not task_id and not title:
        raise ValueError("Informe task_id ou title")
    try:
        if task_id:
            task = IncidentTask.objects.get(pk=task_id, incident=incident)
        else:
            task = IncidentTask.objects.filter(incident=incident, title=title).latest("created_at")
    except IncidentTask.DoesNotExist:
        raise ValueError("Tarefa nao encontrada")
    done = step.input.get("done", True)
    actor = context.get("actor")
    update_task(task=task, done=done, actor=actor)
    return {"task_id": task.id, "done": task.done}


@register("communication.log")
def log_communication(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message = step.input.get("message")
    if not message:
        raise ValueError("Mensagem obrigatoria")
    recipient_user = step.input.get("recipient_user") or step.input.get("recipient_user_id")
    recipient_user = _resolve_user(recipient_user) if recipient_user else None
    actor = context.get("actor")
    communication = create_communication(
        incident=incident,
        channel=step.input.get("channel", "internal"),
        recipient_team=step.input.get("recipient_team"),
        recipient_user=recipient_user,
        message=message,
        actor=actor,
    )
    return {
        "communication_id": communication.id,
        "channel": communication.channel,
        "recipient_team": communication.recipient_team,
        "recipient_user": getattr(communication.recipient_user, "username", None),
    }


@register("artifact.create")
def create_artifact(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    value = step.input.get("value")
    if not value:
        raise ValueError("value obrigatorio")
    type_code = step.input.get("type", "OTHER")
    actor = context.get("actor")
    artifact = add_artifact_link(
        incident=incident,
        value=value,
        type_code=type_code,
        actor=actor,
    )
    return {"artifact_id": artifact.id, "type": artifact.type, "value": artifact.value}


@register("artifact.create_email_from_raw")
def create_email_from_raw(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    raw_message = step.input.get("raw_message")
    message, raw_text = _parse_email_message(raw_message)
    headers = _extract_basic_email_headers(message)
    actor = context.get("actor")
    artifact = create_artifact_record(
        incident=incident,
        type_code=Artifact.Type.EMAIL,
        value=step.input.get("value") or _email_artifact_value(headers),
        attributes={
            "email_raw": raw_text,
            "email_headers": headers,
        },
        actor=actor,
    )
    return {
        "artifact_id": artifact.id,
        "type": artifact.type,
        "value": artifact.value,
        "headers": headers,
    }


@register("artifact.parse_email_headers")
def parse_email_headers(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message, _, artifact = _resolve_email_source(step=step, context=context, incident=incident)
    headers = _extract_basic_email_headers(message)
    actor = context.get("actor")
    _persist_artifact_attributes(
        artifact=artifact,
        incident=incident,
        actor=actor,
        attributes={"email_headers": headers},
        context=context,
    )
    return {
        "artifact_id": getattr(artifact, "id", None),
        "headers": headers,
    }


@register("artifact.extract_links")
def extract_links(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message, _, artifact = _resolve_email_source(step=step, context=context, incident=incident)
    links = _extract_links_from_message(message)
    actor = context.get("actor")
    _persist_artifact_attributes(
        artifact=artifact,
        incident=incident,
        actor=actor,
        attributes={"email_links": links},
        context=context,
    )
    return {
        "artifact_id": getattr(artifact, "id", None),
        "links": links,
    }


@register("artifact.extract_attachments_metadata")
def extract_attachments_metadata(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message, _, artifact = _resolve_email_source(step=step, context=context, incident=incident)
    attachments = _extract_attachment_metadata(message)
    actor = context.get("actor")
    _persist_artifact_attributes(
        artifact=artifact,
        incident=incident,
        actor=actor,
        attributes={"email_attachments": attachments},
        context=context,
    )
    return {
        "artifact_id": getattr(artifact, "id", None),
        "attachments": attachments,
    }


@register("artifact.extract_iocs_from_email")
def extract_iocs_from_email(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    message, _, artifact = _resolve_email_source(step=step, context=context, incident=incident)
    headers = _extract_basic_email_headers(message)
    links = _extract_links_from_message(message)
    attachments = _extract_attachment_metadata(message)
    iocs = {
        "urls": links,
        "domains": _extract_domain_candidates(message, links, headers),
        "ips": _extract_ip_candidates(message, links, headers),
        "filenames": _dedupe_strings(item.get("filename") for item in attachments if item.get("filename")),
        "attachments": attachments,
    }
    actor = context.get("actor")
    _persist_artifact_attributes(
        artifact=artifact,
        incident=incident,
        actor=actor,
        attributes={"email_iocs": iocs},
        context=context,
    )
    return {
        "artifact_id": getattr(artifact, "id", None),
        "iocs": iocs,
    }


@register("artifact.update_attributes")
def update_artifact_action_attributes(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    attributes = step.input.get("attributes")
    if not isinstance(attributes, dict):
        raise ValueError("attributes deve ser um objeto")
    artifact = _resolve_artifact(
        incident=incident,
        context=context,
        artifact_id=step.input.get("artifact_id"),
    )
    merge = step.input.get("merge", True)
    actor = context.get("actor")
    result = update_artifact_attributes(
        artifact=artifact,
        incident=incident,
        attributes=attributes,
        merge=bool(merge),
        actor=actor,
    )
    artifact.refresh_from_db(fields=["attributes"])
    context.setdefault("artifact", {})["attributes"] = artifact.attributes
    return {
        "artifact_id": artifact.id,
        "changed": result.changed,
        "attributes": artifact.attributes,
    }


@register("artifact.update")
def update_artifact_action(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    value = step.input.get("value")
    type_code = step.input.get("type")
    if value is None and not type_code:
        raise ValueError("Informe value ou type")
    artifact = _resolve_artifact(
        incident=incident,
        context=context,
        artifact_id=step.input.get("artifact_id"),
    )
    actor = context.get("actor")
    result = update_artifact(
        artifact=artifact,
        incident=incident,
        value=value,
        type_code=type_code,
        actor=actor,
    )
    artifact.refresh_from_db(fields=["type", "value"])
    artifact_entry = context.setdefault("artifact", {})
    artifact_entry["type"] = artifact.type
    artifact_entry["value"] = artifact.value
    return {
        "artifact_id": artifact.id,
        "changed": result.changed,
        "type": artifact.type,
        "value": artifact.value,
    }


@register("artifact.update_hash")
def update_artifact_hash_action(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    sha256 = step.input.get("sha256")
    artifact = _resolve_artifact(
        incident=incident,
        context=context,
        artifact_id=step.input.get("artifact_id"),
    )
    actor = context.get("actor")
    result = update_artifact_hash(
        artifact=artifact,
        incident=incident,
        sha256=sha256,
        actor=actor,
    )
    artifact.refresh_from_db(fields=["sha256"])
    context.setdefault("artifact", {})["sha256"] = artifact.sha256
    return {
        "artifact_id": artifact.id,
        "changed": result.changed,
        "sha256": artifact.sha256,
    }


@register("artifact.extract_domain_from_email")
def extract_domain_from_email(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    email = step.input.get("email")
    if not email:
        source_artifact_id = step.input.get("artifact_id")
        if source_artifact_id:
            try:
                artifact = incident.artifacts.get(pk=source_artifact_id)
                email = artifact.value
            except incident.artifacts.model.DoesNotExist:
                raise ValueError("Artefato de email nao encontrado")
    if not email or "@" not in email:
        raise ValueError("Email invalido para extrair dominio")
    domain = email.split("@", 1)[1].strip().lower()
    actor = context.get("actor")
    artifact = add_artifact_link(
        incident=incident,
        value=domain,
        type_code="DOMAIN",
        actor=actor,
    )
    incident.add_label("domain-extracted", actor=actor)
    return {"domain": domain, "artifact_id": artifact.id}
