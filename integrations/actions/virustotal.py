from __future__ import annotations

import base64
import ipaddress
import os
import re
import time
from typing import Any, Dict

import requests

from django.utils import timezone

from incidents.models import Artifact, TimelineEntry
from incidents.services import update_artifact_attributes

from ..registry import register

VT_BASE_URL = "https://www.virustotal.com/api/v3"
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")


def _reputation_from_stats(stats: dict | None, fallback: str = "harmless") -> str:
    stats = stats or {}
    if stats.get("malicious", 0):
        return "malicious"
    if stats.get("suspicious", 0):
        return "suspicious"
    if stats.get("undetected", 0):
        return fallback
    if stats.get("harmless", 0):
        return "harmless"
    return fallback


def _compact_stats(stats: dict | None) -> dict[str, int]:
    template = {"harmless": 0, "suspicious": 0, "malicious": 0, "undetected": 0}
    if not stats:
        return template
    compact = template.copy()
    for key in compact:
        try:
            compact[key] = int(stats.get(key, 0))
        except (TypeError, ValueError):
            compact[key] = 0
    return compact


def _build_vt_attributes(
    *,
    indicator: str,
    indicator_type: str,
    reputation: str,
    extra: dict | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "indicator": {"type": indicator_type, "value": indicator},
        "reputation": reputation,
        "fetched_at": timezone.now().isoformat(),
        "source": "virustotal",
    }
    if extra:
        for key, value in extra.items():
            if value in (None, "", [], {}):
                continue
            payload[key] = value
    return payload




def _require_incident(context: Dict[str, Any]):
    incident = context.get("incident")
    if not incident:
        raise ValueError("Contexto sem incidente")
    return incident


def _ensure_api_key() -> str:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        raise ValueError("VIRUSTOTAL_API_KEY nao configurada")
    return api_key


def _fetch(endpoint: str) -> dict[str, Any]:
    api_key = _ensure_api_key()
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(endpoint, headers=headers, timeout=15)
    except requests.RequestException as exc:
        raise ValueError(f"Erro ao consultar VirusTotal: {exc}") from exc
    if response.status_code == 404:
        return {"not_found": True, "status_code": 404}
    if response.status_code >= 400:
        raise ValueError(
            f"VirusTotal respondeu {response.status_code}: {response.text[:200]}"
        )
    try:
        return response.json()
    except ValueError as exc:
        raise ValueError("Resposta do VirusTotal nao eh JSON valido") from exc


def _normalize_domain(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    domain = str(raw).strip()
    domain = domain.strip("\"'")
    while domain.lower().startswith("b'") or domain.lower().startswith('b"'):
        domain = domain[2:]
        domain = domain.strip("\"'")
    domain = domain.replace('"', "").replace("'", "")
    domain = domain.lower()
    if not DOMAIN_PATTERN.match(domain) or "." not in domain:
        raise ValueError(f"Dominio invalido para consulta no VirusTotal: {domain!r}")
    return domain


def _normalize_ip(raw: str | bytes | None) -> str:
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    ip_value = str(raw).strip()
    ip_value = ip_value.strip("\"'")
    while ip_value.lower().startswith("b'") or ip_value.lower().startswith('b"'):
        ip_value = ip_value[2:]
        ip_value = ip_value.strip("\"'")
    return ip_value.strip()


def _encode_url_id(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        raise ValueError("URL nao pode ser vazia")
    encoded = base64.urlsafe_b64encode(cleaned.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def _submit_file(file_obj, filename: str | None) -> str:
    api_key = _ensure_api_key()
    headers = {"x-apikey": api_key}
    files = {"file": (filename or "artifact.bin", file_obj)}
    try:
        response = requests.post(
            f"{VT_BASE_URL}/files",
            headers=headers,
            files=files,
            timeout=120,
        )
    except requests.RequestException as exc:
        raise ValueError(f"Erro ao enviar arquivo para VirusTotal: {exc}") from exc
    if response.status_code >= 400:
        raise ValueError(
            f"VirusTotal (upload) respondeu {response.status_code}: {response.text[:200]}"
        )
    data = response.json()
    analysis_id = data.get("data", {}).get("id")
    if not analysis_id:
        raise ValueError("Resposta do VirusTotal nao retornou analysis_id")
    return analysis_id


def _fetch_analysis(analysis_id: str, attempts: int = 5, delay: float = 3.0) -> dict[str, Any]:
    last_payload: dict[str, Any] = {}
    for _ in range(max(attempts, 1)):
        last_payload = _fetch(f"{VT_BASE_URL}/analyses/{analysis_id}")
        status = last_payload.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            break
        time.sleep(delay)
    return last_payload


@register("virustotal.domain_report")
def domain_report(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    domain = step.input.get("domain")
    if not domain:
        artifact_type = step.input.get("artifact_type", "DOMAIN")
        artifact = incident.artifacts.filter(type=artifact_type).order_by("-created_at").first()
        if not artifact or not artifact.value:
            raise ValueError("Nenhum dominio disponivel para consulta no VirusTotal")
        domain = artifact.value
    domain = _normalize_domain(domain)
    payload = _fetch(f"{VT_BASE_URL}/domains/{domain}")

    stats: dict[str, Any] = {}
    categories: list[str] = []
    whois_created = None
    whois_expires = None
    registrar = None
    domain_status = None
    whois_text = ""
    reputation = None

    if payload and not payload.get("not_found"):
        attributes = payload.get("data", {}).get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        categories = list(attributes.get("categories", {}).values())
        whois_text = attributes.get("whois") or ""
        registration = attributes.get("domain_registration", {}) or {}
        whois_created = registration.get("created_date") or attributes.get("creation_date")
        whois_expires = registration.get("expires_date") or attributes.get("expiration_date")
        registrar = registration.get("registrar") or attributes.get("registrar")
        domain_status = registration.get("status")
        reputation = attributes.get("reputation")

    reputation = reputation or _reputation_from_stats(stats, "harmless")
    compact_stats = _compact_stats(stats)
    note = (
        f"VirusTotal consultei dominio {domain}: "
        f"malicious={compact_stats.get('malicious', 0)}, suspicious={compact_stats.get('suspicious', 0)}, "
        f"harmless={compact_stats.get('harmless', 0)}"
    )
    actor = context.get("actor")
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.NOTE,
        message=note,
        actor=actor,
        extra={
            "source": "virustotal",
            "domain": domain,
            "stats": compact_stats,
            "categories": categories[:5],
            "whois": {
                "registrar": registrar,
                "created": whois_created,
                "expires": whois_expires,
                "status": domain_status,
            },
            "whois_text": whois_text or None,
        },
    )
    artifact_obj = context.get("artifact_instance")
    if artifact_obj is None:
        artifact_info = context.get("artifact") or {}
        artifact_id = artifact_info.get("id")
        if artifact_id:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()
    if artifact_obj:
        vt_attributes = _build_vt_attributes(
            indicator=domain,
            indicator_type="domain",
            reputation=reputation,
            extra={
                "categories": categories[:5],
                "whois_created": whois_created,
                "whois_expires": whois_expires,
                "registrar": registrar,
                "status": domain_status,
                "last_analysis": compact_stats,
            },
        )
        update_artifact_attributes(
            artifact=artifact_obj,
            incident=incident,
            attributes={"virustotal": vt_attributes},
            actor=actor,
        )
        artifact_entry = context.setdefault("artifact", {})
        artifact_entry["attributes"] = artifact_obj.attributes
    return {
        "domain": domain,
        "reputation": reputation,
        "stats": compact_stats,
        "categories": categories[:5],
        "whois": {
            "registrar": registrar,
            "created": whois_created,
            "expires": whois_expires,
            "status": domain_status,
        },
        "whois_text": whois_text or None,
        "not_found": payload.get("not_found", False),
    }


@register("virustotal.ip_report")
def ip_report(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    ip_value = step.input.get("ip")
    if not ip_value:
        artifact_type = step.input.get("artifact_type", "IP")
        artifact = (
            incident.artifacts.filter(type=artifact_type)
            .order_by("-created_at")
            .first()
        )
        if not artifact or not artifact.value:
            raise ValueError("Nenhum IP disponivel para consulta no VirusTotal")
        ip_value = artifact.value
    ip_value = _normalize_ip(ip_value)
    try:
        ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise ValueError(f"IP invalido '{ip_value}'") from exc

    payload = _fetch(f"{VT_BASE_URL}/ip_addresses/{ip_value}")

    reputation = None
    stats: dict[str, Any] = {}
    attributes: dict[str, Any] = {}
    if payload and not payload.get("not_found"):
        attributes = payload.get("data", {}).get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        reputation = attributes.get("reputation")

    reputation = reputation or _reputation_from_stats(stats, "harmless")
    compact_stats = _compact_stats(stats)

    note = (
        f"VirusTotal consultei IP {ip_value}: "
        f"malicious={compact_stats.get('malicious', 0)}, suspicious={compact_stats.get('suspicious', 0)}, "
        f"harmless={compact_stats.get('harmless', 0)}"
    )
    actor = context.get("actor")
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.NOTE,
        message=note,
        actor=actor,
        extra={
            "source": "virustotal",
            "ip": ip_value,
            "stats": compact_stats,
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "network": attributes.get("network"),
            "reputation": reputation,
            "fetched_at": timezone.now().isoformat(),
        },
    )
    artifact_obj = context.get("artifact_instance")
    if artifact_obj is None:
        artifact_info = context.get("artifact") or {}
        artifact_id = artifact_info.get("id")
        if artifact_id:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()
    if artifact_obj:
        vt_attributes = _build_vt_attributes(
            indicator=ip_value,
            indicator_type="ip",
            reputation=reputation,
            extra={
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
                "last_analysis": compact_stats,
            },
        )
        update_artifact_attributes(
            artifact=artifact_obj,
            incident=incident,
            attributes={"virustotal": vt_attributes},
            actor=actor,
        )
        artifact_entry = context.setdefault("artifact", {})
        artifact_entry["attributes"] = artifact_obj.attributes
    return {
        "ip": ip_value,
        "stats": compact_stats,
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "reputation": reputation,
        "not_found": payload.get("not_found", False),
    }


@register("virustotal.file_upload")
def file_upload(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    artifact_obj = context.get("artifact_instance")
    if artifact_obj is None:
        artifact_info = context.get("artifact") or {}
        artifact_id = artifact_info.get("id")
        if artifact_id:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()
    if artifact_obj is None:
        raise ValueError("Artefato nao encontrado para upload")
    if not artifact_obj.file:
        raise ValueError("Artefato nao possui arquivo anexado")

    filename = os.path.basename(artifact_obj.file.name or "artifact.bin")
    artifact_obj.file.open("rb")
    try:
        analysis_id = _submit_file(artifact_obj.file, filename)
    finally:
        artifact_obj.file.close()

    analysis_payload = _fetch_analysis(analysis_id)
    analysis_attr = analysis_payload.get("data", {}).get("attributes", {}) or {}
    status = analysis_attr.get("status") or "queued"
    stats = analysis_attr.get("stats") or analysis_attr.get("results") or {}
    compact_stats = _compact_stats(stats)
    reputation = _reputation_from_stats(compact_stats, "harmless")

    metadata = analysis_attr.get("metadata", {}) or {}
    file_info = metadata.get("file_info") or {}
    sha256 = file_info.get("sha256") or artifact_obj.sha256 or analysis_attr.get("sha256")
    meaningful_name = file_info.get("name") or analysis_attr.get("meaningful_name") or filename
    file_type = file_info.get("type") or analysis_attr.get("type")
    size = file_info.get("size") or analysis_attr.get("size")

    if not artifact_obj.sha256 and sha256:
        artifact_obj.sha256 = sha256
        artifact_obj.save(update_fields=["sha256"])

    note = f"VirusTotal envio de arquivo {meaningful_name} (analysis {analysis_id}) - status {status}"
    actor = context.get("actor")
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.NOTE,
        message=note,
        actor=actor,
        extra={
            "source": "virustotal",
            "analysis_id": analysis_id,
            "analysis_status": status,
            "stats": compact_stats,
            "sha256": sha256,
            "meaningful_name": meaningful_name,
        },
    )

    vt_attributes = _build_vt_attributes(
        indicator=sha256 or meaningful_name,
        indicator_type="file",
        reputation=reputation,
        extra={
            "analysis_id": analysis_id,
            "analysis_status": status,
            "meaningful_name": meaningful_name,
            "type": file_type,
            "size": size,
            "last_analysis": compact_stats,
            "sha256": sha256,
        },
    )
    update_artifact_attributes(
        artifact=artifact_obj,
        incident=incident,
        attributes={"virustotal": vt_attributes},
        actor=actor,
    )
    artifact_entry = context.setdefault("artifact", {})
    artifact_entry["attributes"] = artifact_obj.attributes
    return {
        "analysis_id": analysis_id,
        "analysis_status": status,
        "reputation": reputation,
        "stats": compact_stats,
        "sha256": sha256,
        "meaningful_name": meaningful_name,
    }


@register("virustotal.url_report")
def url_report(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    url_value = step.input.get("url")
    artifact_obj = None
    if not url_value:
        artifact_type = step.input.get("artifact_type", Artifact.Type.URL)
        artifact_obj = (
            incident.artifacts.filter(type=artifact_type)
            .order_by("-created_at")
            .first()
        )
        if not artifact_obj or not artifact_obj.value:
            raise ValueError("Nenhuma URL disponivel para consulta no VirusTotal")
        url_value = artifact_obj.value
    url_value = str(url_value).strip()
    url_id = _encode_url_id(url_value)

    payload = _fetch(f"{VT_BASE_URL}/urls/{url_id}")

    stats: dict[str, Any] = {}
    attributes: dict[str, Any] = {}
    reputation = None
    last_final_url = None
    response_code = None
    if payload and not payload.get("not_found"):
        attributes = payload.get("data", {}).get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        reputation = attributes.get("reputation")
        last_final_url = attributes.get("last_final_url")
        response_code = attributes.get("last_http_response_code")
    reputation = reputation or _reputation_from_stats(stats, "harmless")
    compact_stats = _compact_stats(stats)

    note = (
        f"VirusTotal consultei URL {url_value}: "
        f"malicious={compact_stats.get('malicious', 0)}, suspicious={compact_stats.get('suspicious', 0)}, "
        f"harmless={compact_stats.get('harmless', 0)}"
    )
    actor = context.get("actor")
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.NOTE,
        message=note,
        actor=actor,
        extra={
            "source": "virustotal",
            "url": url_value,
            "stats": compact_stats,
            "last_http_response_code": response_code,
            "last_final_url": last_final_url,
            "reputation": reputation,
        },
    )
    if artifact_obj is None:
        artifact_info = context.get("artifact") or {}
        artifact_id = artifact_info.get("id")
        if artifact_id:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()
    if artifact_obj:
        vt_attributes = _build_vt_attributes(
            indicator=url_value,
            indicator_type="url",
            reputation=reputation,
            extra={
                "last_analysis": compact_stats,
                "last_final_url": last_final_url,
                "last_http_response_code": response_code,
            },
        )
        update_artifact_attributes(
            artifact=artifact_obj,
            incident=incident,
            attributes={"virustotal": vt_attributes},
            actor=actor,
        )
        artifact_entry = context.setdefault("artifact", {})
        artifact_entry["attributes"] = artifact_obj.attributes
    return {
        "url": url_value,
        "reputation": reputation,
        "stats": compact_stats,
        "last_final_url": last_final_url,
        "last_http_response_code": response_code,
        "not_found": payload.get("not_found", False),
    }


@register("virustotal.file_report")
def file_report(*, step, context: Dict[str, Any]):
    incident = _require_incident(context)
    file_hash = step.input.get("hash")
    artifact_obj = None
    artifact_type = step.input.get("artifact_type") or Artifact.Type.FILE
    if not file_hash:
        artifact_obj = (
            incident.artifacts.filter(type=artifact_type)
            .order_by("-created_at")
            .first()
        )
        if not artifact_obj:
            raise ValueError("Nenhum artefato disponivel para consulta no VirusTotal")
        if artifact_type == Artifact.Type.HASH:
            file_hash = artifact_obj.value
        else:
            file_hash = artifact_obj.sha256 or artifact_obj.value
        if not file_hash:
            raise ValueError("Artefato selecionado nao possui hash para consulta")
    file_hash = str(file_hash).strip().lower()

    payload = _fetch(f"{VT_BASE_URL}/files/{file_hash}")
    if payload.get("not_found"):
        raise ValueError("Arquivo não encontrado no VirusTotal")

    attributes = payload.get("data", {}).get("attributes", {}) or {}
    stats = attributes.get("last_analysis_stats", {}) or {}
    reputation = attributes.get("reputation") or _reputation_from_stats(stats, "harmless")
    compact_stats = _compact_stats(stats)
    meaningful_name = attributes.get("meaningful_name")
    type_description = attributes.get("type_description")
    size = attributes.get("size")

    note = (
        f"VirusTotal consultei hash {file_hash}: "
        f"malicious={compact_stats.get('malicious', 0)}, suspicious={compact_stats.get('suspicious', 0)}, "
        f"harmless={compact_stats.get('harmless', 0)}"
    )
    actor = context.get("actor")
    incident.log_timeline(
        entry_type=TimelineEntry.EntryType.NOTE,
        message=note,
        actor=actor,
        extra={
            "source": "virustotal",
            "hash": file_hash,
            "stats": compact_stats,
            "meaningful_name": meaningful_name,
            "type_description": type_description,
            "size": size,
            "reputation": reputation,
        },
    )
    if artifact_obj is None:
        artifact_info = context.get("artifact") or {}
        artifact_id = artifact_info.get("id")
        if artifact_id:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()
    if artifact_obj:
        vt_attributes = _build_vt_attributes(
            indicator=file_hash,
            indicator_type="file",
            reputation=reputation,
            extra={
                "meaningful_name": meaningful_name,
                "type_description": type_description,
                "size": size,
                "last_analysis": compact_stats,
            },
        )
        update_artifact_attributes(
            artifact=artifact_obj,
            incident=incident,
            attributes={"virustotal": vt_attributes},
            actor=actor,
        )
        artifact_entry = context.setdefault("artifact", {})
        artifact_entry["attributes"] = artifact_obj.attributes
    return {
        "hash": file_hash,
        "reputation": reputation,
        "stats": compact_stats,
        "meaningful_name": meaningful_name,
        "type_description": type_description,
        "size": size,
    }
