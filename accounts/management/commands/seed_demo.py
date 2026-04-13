from __future__ import annotations

import os

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from accounts.models import User
from incidents.models import Artifact, Incident, TimelineEntry
from incidents.services import add_artifact_link, create_artifact_record, update_artifact_attributes
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Playbook


class Command(BaseCommand):
    help = "Create demo data for basilio-soar"
    AUTO_PLAYBOOK_BLOCK_LABEL = "manual-treatment"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Permite executar o seed mesmo sem ALLOW_DEMO_SEED=1.",
        )
        parser.add_argument(
            "--structures-only",
            action="store_true",
            help="Semeia apenas estruturas (usuarios, secrets, conectores e playbooks).",
        )
        parser.add_argument(
            "--incidents-only",
            action="store_true",
            help="Semeia apenas incidentes demo.",
        )
        parser.add_argument(
            "--phishing-comparison",
            action="store_true",
            help="Semeia apenas o cenario comparativo de phishing (AUTO x MANUAL) com artefatos de entrada estilo SIEM.",
        )

    @staticmethod
    def _seed_allowed(force: bool) -> bool:
        return force or os.getenv("ALLOW_DEMO_SEED", "").strip() == "1"

    @classmethod
    def _apply_manual_treatment_guard_to_automatic(cls, dsl: dict) -> dict:
        if (dsl or {}).get("mode") != "automatic":
            return dsl
        for trigger in dsl.get("triggers", []) or []:
            filters = trigger.get("filters") or {}
            exclude_labels = list(filters.get("exclude_labels") or [])
            if cls.AUTO_PLAYBOOK_BLOCK_LABEL not in exclude_labels:
                exclude_labels.append(cls.AUTO_PLAYBOOK_BLOCK_LABEL)
            filters["exclude_labels"] = exclude_labels
            trigger["filters"] = filters
        return dsl

    def _seed_users(self) -> tuple[User, User, User]:
        admin, _ = User.objects.get_or_create(
            username="admin",
            defaults={
                "email": "admin@example.com",
                "role": User.Roles.ADMIN,
                "is_superuser": True,
                "is_staff": True,
            },
        )
        if not admin.check_password("admin123"):
            admin.set_password("admin123")
            admin.display_name = "Admin"
            admin.save()
        self.stdout.write(" - admin / admin123")

        lead, _ = User.objects.get_or_create(
            username="soclead",
            defaults={
                "email": "lead@example.com",
                "role": User.Roles.SOC_LEAD,
                "is_staff": True,
            },
        )
        if not lead.check_password("soclead123"):
            lead.set_password("soclead123")
            lead.display_name = "SOC Lead"
            lead.save()
        self.stdout.write(" - soclead / soclead123")

        analyst, _ = User.objects.get_or_create(
            username="analyst",
            defaults={
                "email": "analyst@example.com",
                "role": User.Roles.SOC_ANALYST,
            },
        )
        if not analyst.check_password("analyst123"):
            analyst.set_password("analyst123")
            analyst.display_name = "SOC Analyst"
            analyst.save()
        self.stdout.write(" - analyst / analyst123")
        return admin, lead, analyst

    def _seed_incidents(
        self,
        *,
        admin: User,
        lead: User,
        analyst: User,
        phishing_comparison_only: bool = False,
    ) -> None:
        sample_email_raw = (
            "From: \"Seguranca TI\" <security@example.com>\n"
            "Reply-To: support@secure-login-example.net\n"
            "To: colaborador@empresa.local\n"
            "Subject: Atualizacao urgente de senha\n"
            "Message-ID: <seed-phishing@example.com>\n"
            "Received: from 198.51.100.24 by mx.empresa.local\n"
            "Received-SPF: pass (sender SPF authorized)\n"
            "Authentication-Results: mx.empresa.local; spf=pass smtp.mailfrom=example.com; dkim=pass; dmarc=pass\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "\n"
            "Acesse https://secure-login-example.net/reset e confirme seus dados.\n"
        )

        default_incidents_seed = [
            {
                "title": "Email suspeito de phishing",
                "description": "Colaborador reportou email solicitando redefinicao de senha.",
                "severity": Incident.Severity.MEDIUM,
                "status": Incident.Status.IN_PROGRESS,
                "labels": ["phishing", "email"],
                "preset_enrichment": True,
                "artifacts": [
                    {"type": Artifact.Type.EMAIL, "value": "<seed-phishing@example.com>", "raw_message": sample_email_raw},
                    {"type": Artifact.Type.URL, "value": "https://primeup.com"},
                    {"type": Artifact.Type.DOMAIN, "value": "primeup.com"},
                ],
                "notes": [
                    "Email encaminhado pelo colaborador.",
                    "Solicitada analise do dominio suspeito.",
                ],
            },
            {
                "title": "Phishing com suspeita de roubo de credenciais",
                "description": "Usuario informou clique em link e possivel digitacao de senha.",
                "severity": Incident.Severity.HIGH,
                "status": Incident.Status.NEW,
                "labels": ["phishing", "credential-compromise"],
                "preset_enrichment": True,
                "artifacts": [
                    {"type": Artifact.Type.IP, "value": "203.0.113.45"},
                ],
                "notes": ["Investigacao inicial pendente."],
            },
            {
                "title": "Possivel BEC com alteracao bancaria",
                "description": "Pedido de mudanca bancaria recebido por thread aparentemente legitima.",
                "severity": Incident.Severity.HIGH,
                "status": Incident.Status.NEW,
                "labels": ["phishing", "bec", "finance-fraud"],
                "preset_enrichment": True,
                "artifacts": [
                    {"type": Artifact.Type.DOMAIN, "value": "supplier-update.example"},
                    {"type": Artifact.Type.EMAIL, "value": "finance-update@example.net"},
                ],
                "notes": ["Financeiro deve validar a alteracao fora de banda imediatamente."],
            },
        ]

        phishing_comparison_seed = [
            {
                "title": "Comparativo phishing - AUTO",
                "description": "Incidente para comparar fluxo automatizado contra fluxo manual espelho.",
                "severity": Incident.Severity.MEDIUM,
                "status": Incident.Status.NEW,
                "labels": ["phishing", "email", "auto-treatment"],
                "preset_enrichment": False,
                "artifacts": [
                    {
                        "type": Artifact.Type.EMAIL,
                        "value": "<compare-auto-phishing@example.com>",
                        "raw_message": sample_email_raw,
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-AUTO-001",
                            "detection_rule": "mail_suspicious_link_correlation",
                        },
                    },
                    {
                        "type": Artifact.Type.URL,
                        "value": "https://compare-auto.example/reset",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-AUTO-001",
                            "ioc_origin": "email_body",
                        },
                    },
                    {
                        "type": Artifact.Type.DOMAIN,
                        "value": "compare-auto.example",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-AUTO-001",
                            "ioc_origin": "email_link",
                        },
                    },
                    {
                        "type": Artifact.Type.IP,
                        "value": "203.0.113.88",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-AUTO-001",
                            "ioc_origin": "mail_gateway_trace",
                        },
                    },
                ],
                "notes": [
                    "Caso de comparacao originado por alerta SIEM; fluxo automatico habilitado.",
                    "Nao aplicar tarefas manuais de espelho neste incidente.",
                ],
            },
            {
                "title": "Comparativo phishing - MANUAL",
                "description": "Incidente para comparar fluxo manual espelho contra automacoes.",
                "severity": Incident.Severity.MEDIUM,
                "status": Incident.Status.NEW,
                "labels": ["phishing", "email", "manual-treatment"],
                "preset_enrichment": False,
                "artifacts": [
                    {
                        "type": Artifact.Type.EMAIL,
                        "value": "<compare-manual-phishing@example.com>",
                        "raw_message": sample_email_raw,
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-MANUAL-001",
                            "detection_rule": "mail_suspicious_link_correlation",
                        },
                    },
                    {
                        "type": Artifact.Type.URL,
                        "value": "https://compare-manual.example/reset",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-MANUAL-001",
                            "ioc_origin": "email_body",
                        },
                    },
                    {
                        "type": Artifact.Type.DOMAIN,
                        "value": "compare-manual.example",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-MANUAL-001",
                            "ioc_origin": "email_link",
                        },
                    },
                    {
                        "type": Artifact.Type.IP,
                        "value": "203.0.113.89",
                        "attributes": {
                            "siem_source": "SOC-SIEM",
                            "alert_id": "SIM-PHISH-MANUAL-001",
                            "ioc_origin": "mail_gateway_trace",
                        },
                    },
                ],
                "notes": [
                    "Caso de comparacao originado por alerta SIEM; automacoes bloqueadas por label manual-treatment.",
                    "Executar playbook manual espelho para reproduzir as etapas automaticamente.",
                ],
            },
        ]

        incidents_seed = phishing_comparison_seed if phishing_comparison_only else (default_incidents_seed + phishing_comparison_seed)

        for payload in incidents_seed:
            incident, created = Incident.objects.get_or_create(
                title=payload["title"],
                defaults={
                    "description": payload["description"],
                    "severity": payload["severity"],
                    "status": payload["status"],
                    "labels": payload["labels"],
                    "created_by": admin,
                    "assignee": lead,
                },
            )
            if created:
                self.stdout.write(f" - Incident '{incident.title}'")
            for artifact_payload in payload["artifacts"]:
                if artifact_payload["type"] == Artifact.Type.EMAIL and artifact_payload.get("raw_message"):
                    email_attributes = {"email_raw": artifact_payload["raw_message"]}
                    if artifact_payload.get("attributes"):
                        email_attributes.update(artifact_payload["attributes"])
                    artifact_obj = incident.artifacts.filter(
                        type=artifact_payload["type"],
                        value=artifact_payload["value"],
                    ).first()
                    if artifact_obj is None:
                        artifact_obj = create_artifact_record(
                            incident=incident,
                            type_code=artifact_payload["type"],
                            value=artifact_payload["value"],
                            attributes=email_attributes,
                            actor=analyst,
                        )
                    else:
                        update_artifact_attributes(
                            artifact=artifact_obj,
                            incident=incident,
                            attributes=email_attributes,
                            actor=analyst,
                        )
                else:
                    artifact_obj = add_artifact_link(
                        incident=incident,
                        value=artifact_payload["value"],
                        type_code=artifact_payload["type"],
                        actor=analyst,
                    )
                    if artifact_payload.get("attributes"):
                        update_artifact_attributes(
                            artifact=artifact_obj,
                            incident=incident,
                            attributes=artifact_payload["attributes"],
                            actor=analyst,
                        )
                if payload.get("preset_enrichment", True) and artifact_obj.type == Artifact.Type.DOMAIN:
                    update_artifact_attributes(
                        artifact=artifact_obj,
                        incident=incident,
                        attributes={
                            "virustotal": {
                                "type": "domain",
                                "value": artifact_obj.value,
                                "reputation": "malicious",
                                "categories": ["phishing"],
                                "source": "seed-demo",
                            }
                        },
                        actor=analyst,
                    )
                if payload.get("preset_enrichment", True) and artifact_obj.type == Artifact.Type.IP:
                    update_artifact_attributes(
                        artifact=artifact_obj,
                        incident=incident,
                        attributes={
                            "virustotal": {
                                "type": "ip",
                                "value": artifact_obj.value,
                                "reputation": "suspicious",
                                "source": "seed-demo",
                            }
                        },
                        actor=analyst,
                    )
            if created:
                for note in payload["notes"]:
                    TimelineEntry.objects.create(
                        incident=incident,
                        entry_type=TimelineEntry.EntryType.NOTE,
                        message=note,
                        created_by=analyst,
                    )

    @transaction.atomic
    def handle(self, *args, **options):
        force = bool(options.get("force"))
        structures_only = bool(options.get("structures_only"))
        incidents_only = bool(options.get("incidents_only"))
        phishing_comparison = bool(options.get("phishing_comparison"))

        if structures_only and incidents_only:
            raise CommandError("Use apenas uma opcao: --structures-only ou --incidents-only.")
        if structures_only and phishing_comparison:
            raise CommandError("A opcao --phishing-comparison nao pode ser usada com --structures-only.")

        if not self._seed_allowed(force=force):
            raise CommandError(
                "Execucao bloqueada. Defina ALLOW_DEMO_SEED=1 ou execute com --force."
            )
        if phishing_comparison:
            self.stdout.write(self.style.MIGRATE_HEADING("Seeding phishing comparison incidents"))
        elif structures_only:
            self.stdout.write(self.style.MIGRATE_HEADING("Seeding demo structures"))
        elif incidents_only:
            self.stdout.write(self.style.MIGRATE_HEADING("Seeding demo incidents"))
        else:
            self.stdout.write(self.style.MIGRATE_HEADING("Seeding demo data"))

        admin, lead, analyst = self._seed_users()

        if phishing_comparison:
            self._seed_incidents(
                admin=admin,
                lead=lead,
                analyst=analyst,
                phishing_comparison_only=True,
            )
            self.stdout.write(self.style.SUCCESS("Incidentes de comparacao de phishing prontos."))
            return

        if incidents_only:
            self._seed_incidents(admin=admin, lead=lead, analyst=analyst)
            self.stdout.write(self.style.SUCCESS("Incidentes demo prontos."))
            return

        vt_api_key = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip() or "seed-demo-virustotal-api-key"
        if vt_api_key == "seed-demo-virustotal-api-key":
            self.stdout.write(
                self.style.WARNING(
                    " - VIRUSTOTAL_API_KEY ausente; seed usara um secret placeholder para os conectores HTTP."
                )
            )

        vt_secret, created = IntegrationSecretRef.objects.get_or_create(
            name="VIRUSTOTAL_API_KEY",
            defaults={
                "description": "API key usada pelos conectores HTTP de consulta ao VirusTotal.",
                "enabled": True,
                "created_by": lead,
            },
        )
        vt_secret.description = "API key usada pelos conectores HTTP de consulta ao VirusTotal."
        vt_secret.enabled = True
        if vt_secret.created_by is None:
            vt_secret.created_by = lead
        current_secret_value = vt_secret.get_credential().get("token") if vt_secret.has_credential and vt_secret.credential_kind == IntegrationSecretRef.CredentialKind.TOKEN else None
        vt_secret.credential_kind = IntegrationSecretRef.CredentialKind.TOKEN
        if current_secret_value != vt_api_key:
            vt_secret.set_token_credential(vt_api_key)
            vt_secret.rotated_by = lead
            vt_secret.rotated_at = timezone.now()
        vt_secret.full_clean()
        vt_secret.save()
        self.stdout.write(" - Secret 'VIRUSTOTAL_API_KEY'")

        connector_definitions = [
            {
                "name": "VirusTotal Domain Lookup",
                "action_name": "virustotal_config.domain_lookup",
                "method": IntegrationDefinition.Method.GET,
                "auth_strategy": IntegrationDefinition.AuthStrategy.HEADER,
                "auth_header_name": "x-apikey",
                "expected_params": ["domain"],
                "request_template": {
                    "url": "https://www.virustotal.com/api/v3/domains/{{params.domain}}",
                },
                "output_template": {
                    "domain": "{{response.body.data.id}}",
                    "reputation": "{{response.body.data.attributes.reputation}}",
                    "stats": "{{response.body.data.attributes.last_analysis_stats}}",
                    "registrar": "{{response.body.data.attributes.registrar|default:'desconhecido'}}",
                },
            },
            {
                "name": "VirusTotal IP Lookup",
                "action_name": "virustotal_config.ip_lookup",
                "method": IntegrationDefinition.Method.GET,
                "auth_strategy": IntegrationDefinition.AuthStrategy.HEADER,
                "auth_header_name": "x-apikey",
                "expected_params": ["ip"],
                "request_template": {
                    "url": "https://www.virustotal.com/api/v3/ip_addresses/{{params.ip}}",
                },
                "output_template": {
                    "ip": "{{response.body.data.id}}",
                    "reputation": "{{response.body.data.attributes.reputation}}",
                    "stats": "{{response.body.data.attributes.last_analysis_stats}}",
                    "asn": "{{response.body.data.attributes.asn|default:'sem_asn'}}",
                },
            },
            {
                "name": "VirusTotal URL Submit",
                "action_name": "virustotal_config.url_submit",
                "method": IntegrationDefinition.Method.POST,
                "auth_strategy": IntegrationDefinition.AuthStrategy.HEADER,
                "auth_header_name": "x-apikey",
                "expected_params": ["url"],
                "request_template": {
                    "url": "https://www.virustotal.com/api/v3/urls",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": "url={{params.url}}",
                },
                "output_template": {
                    "analysis_id": "{{response.body.data.id}}",
                    "self": "{{response.body.data.links.self}}",
                },
            },
            {
                "name": "VirusTotal URL Report",
                "action_name": "virustotal_config.url_report",
                "method": IntegrationDefinition.Method.GET,
                "auth_strategy": IntegrationDefinition.AuthStrategy.HEADER,
                "auth_header_name": "x-apikey",
                "expected_params": ["url_id"],
                "request_template": {
                    "url": "https://www.virustotal.com/api/v3/urls/{{params.url_id}}",
                },
                "output_template": {
                    "url_id": "{{response.body.data.id}}",
                    "reputation": "{{response.body.data.attributes.reputation}}",
                    "stats": "{{response.body.data.attributes.last_analysis_stats}}",
                    "categories": "{{response.body.data.attributes.categories}}",
                },
            },
            {
                "name": "VirusTotal File Hash Report",
                "action_name": "virustotal_config.file_hash_report",
                "method": IntegrationDefinition.Method.GET,
                "auth_strategy": IntegrationDefinition.AuthStrategy.HEADER,
                "auth_header_name": "x-apikey",
                "expected_params": ["hash"],
                "request_template": {
                    "url": "https://www.virustotal.com/api/v3/files/{{params.hash}}",
                },
                "output_template": {
                    "hash": "{{response.body.data.id}}",
                    "meaningful_name": "{{response.body.data.attributes.meaningful_name|default:'sem_nome'}}",
                    "reputation": "{{response.body.data.attributes.reputation|default:0}}",
                    "stats": "{{response.body.data.attributes.last_analysis_stats}}",
                },
            },
        ]

        for connector_data in connector_definitions:
            connector, created = IntegrationDefinition.objects.get_or_create(
                action_name=connector_data["action_name"],
                defaults={
                    "name": connector_data["name"],
                    "description": f"Consulta VirusTotal via conector HTTP: {connector_data['name']}.",
                    "enabled": True,
                    "method": connector_data["method"],
                    "secret_ref": vt_secret,
                    "auth_strategy": connector_data["auth_strategy"],
                    "auth_header_name": connector_data.get("auth_header_name", ""),
                    "auth_prefix": connector_data.get("auth_prefix", ""),
                    "auth_query_param": connector_data.get("auth_query_param", ""),
                    "request_template": connector_data["request_template"],
                    "output_template": connector_data.get("output_template", {}),
                    "expected_params": connector_data["expected_params"],
                    "timeout_seconds": 15,
                    "revision": 1,
                },
            )
            connector.name = connector_data["name"]
            connector.description = f"Consulta VirusTotal via conector HTTP: {connector_data['name']}."
            connector.enabled = True
            connector.method = connector_data["method"]
            connector.secret_ref = vt_secret
            connector.auth_strategy = connector_data["auth_strategy"]
            connector.auth_header_name = connector_data.get("auth_header_name", "")
            connector.auth_prefix = connector_data.get("auth_prefix", "")
            connector.auth_query_param = connector_data.get("auth_query_param", "")
            connector.request_template = connector_data["request_template"]
            connector.output_template = connector_data.get("output_template", {})
            connector.expected_params = connector_data["expected_params"]
            connector.timeout_seconds = 15
            connector.revision = 1
            connector.full_clean()
            connector.save()
            self.stdout.write(f" - Conector HTTP '{connector.action_name}'")

        phishing_dsl = {
            "name": "Phishing triage",
            "type": "incident",
            "mode": "automatic",
            "triggers": [{"event": "incident.created", "filters": {"labels": ["phishing"]}}],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Fluxo automatico de triagem de phishing iniciado."},
                },
                {
                    "name": "set_status",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Triagem inicial de phishing"},
                },
                {
                    "name": "tag_auto",
                    "action": "incident.add_labels",
                    "input": {"labels": ["auto-playbook", "phishing-triage", "needs-evidence"]},
                },
                {
                    "name": "task_preserve_email",
                    "action": "task.create",
                    "input": {"title": "Preservar o email bruto (.eml) e anexar ao incidente", "owner": "analyst"},
                },
                {
                    "name": "task_interview_user",
                    "action": "task.create",
                    "input": {
                        "title": "Perguntar ao usuario se abriu, clicou, baixou, executou, respondeu, digitou senha ou aprovou MFA",
                        "owner": "analyst",
                    },
                },
                {
                    "name": "task_scope_recipients",
                    "action": "task.create",
                    "input": {
                        "title": "Identificar quem mais recebeu, abriu ou clicou na mensagem e registrar o escopo inicial",
                        "owner": "analyst",
                    },
                },
                {
                    "name": "task_create_iocs",
                    "action": "task.create",
                    "input": {
                        "title": "Criar ou revisar artefatos de URL, dominio, IP e anexo a partir das evidencias do email",
                        "owner": "analyst",
                    },
                },
                {
                    "name": "task_branch_decision",
                    "action": "task.create",
                    "input": {
                        "title": "Classificar o ramo do caso como credential-compromise, malware-suspected, BEC ou mailbox-compromise",
                        "owner": "analyst",
                    },
                },
                {
                    "name": "internal_comm",
                    "action": "communication.log",
                    "input": {
                        "channel": "internal",
                        "recipient_team": "SOC",
                        "message": "Triagem inicial de phishing registrada; aguardando coleta de evidencias e definicao do ramo do incidente.",
                    },
                },
            ],
            "on_error": "continue",
        }

        brute_force_dsl = {
            "name": "Credential phishing containment",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["phishing", "credential-compromise"]},
                },
                {
                    "event": "incident.updated",
                    "filters": {
                        "labels": ["phishing", "credential-compromise"],
                        "changed_fields": ["labels"],
                    },
                },
            ],
            "steps": [
                {
                    "name": "set_in_progress",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Tratamento de credential phishing iniciado"},
                },
                {
                    "name": "log_start",
                    "action": "incident.add_note",
                    "input": {"message": "Ramo de phishing com comprometimento de credencial ativado."},
                },
                {
                    "name": "adjust_impact",
                    "action": "incident.update_impact",
                    "input": {"severity": "HIGH", "risk_score": 80, "business_unit": "Identidade"},
                },
                {
                    "name": "add_labels",
                    "action": "incident.add_labels",
                    "input": {"labels": ["identity-response", "account-review"]},
                },
                {
                    "name": "task_disable_account",
                    "action": "task.create",
                    "input": {"title": "Resetar senha e revogar todas as sessoes da conta afetada", "owner": "soclead"},
                },
                {
                    "name": "task_review_mfa",
                    "action": "task.create",
                    "input": {"title": "Revisar metodos MFA, app consent e aplicativos OAuth suspeitos", "owner": "analyst"},
                },
                {
                    "name": "task_review_logs",
                    "action": "task.create",
                    "input": {"title": "Revisar sign-ins, device IDs, App IDs e origem dos acessos apos o clique", "owner": "analyst"},
                },
                {
                    "name": "task_mailbox_persistence",
                    "action": "task.create",
                    "input": {"title": "Revisar forwarding, inbox rules, delegacoes e alteracoes na caixa de email", "owner": "analyst"},
                },
                {
                    "name": "escalate",
                    "action": "incident.escalate",
                    "input": {"level": "tier2", "targets": ["SOC Lead", "IAM"]},
                },
                {
                    "name": "internal_comm",
                    "action": "communication.log",
                    "input": {
                        "channel": "internal",
                        "recipient_team": "IAM",
                        "message": "Possivel roubo de credenciais via phishing; executar reset, revogacao de sessao e revisao de MFA.",
                    },
                },
            ],
            "on_error": "continue",
        }

        manual_phishing_dsl = {
            "name": "Phishing manual checklist",
            "type": "incident",
            "mode": "manual",
            "filters": [{"target": "incident", "conditions": {"labels": ["phishing"], "any_label": ["manual-treatment"]}}],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Fluxo manual espelho de phishing iniciado (sem automacao)."},
                },
                {
                    "name": "set_in_progress_manual",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Fluxo manual espelho de phishing iniciado"},
                },
                {
                    "name": "task_triagem_manual",
                    "action": "task.create",
                    "input": {"title": "TRIAGEM MANUAL: validar relato do usuario, horario do evento, impacto inicial e escopo de destinatarios", "owner": "analyst"},
                },
                {
                    "name": "task_preservar_email",
                    "action": "task.create",
                    "input": {"title": "PRESERVAR EVIDENCIA: anexar .eml bruto no artefato EMAIL e confirmar headers completos", "owner": "analyst"},
                },
                {
                    "name": "task_extrair_ioc_manual",
                    "action": "task.create",
                    "input": {"title": "EXTRACAO MANUAL: identificar URLs, dominios, IPs e anexos do email e criar artefatos manualmente", "owner": "analyst"},
                },
                {
                    "name": "task_enriquecer_domain_manual",
                    "action": "task.create",
                    "input": {"title": "ENRIQUECIMENTO MANUAL (equivalente ao Domain auto enrichment): consultar VirusTotal para cada dominio e registrar atributos no artefato", "owner": "analyst"},
                },
                {
                    "name": "task_enriquecer_ip_manual",
                    "action": "task.create",
                    "input": {"title": "ENRIQUECIMENTO MANUAL (equivalente ao IP auto enrichment): consultar VirusTotal para cada IP e registrar reputacao/estatisticas", "owner": "analyst"},
                },
                {
                    "name": "task_enriquecer_url_manual",
                    "action": "task.create",
                    "input": {"title": "ENRIQUECIMENTO MANUAL (equivalente ao URL auto enrichment): submeter URL no VT, coletar report e registrar no artefato", "owner": "analyst"},
                },
                {
                    "name": "task_enriquecer_hash_manual",
                    "action": "task.create",
                    "input": {"title": "ENRIQUECIMENTO MANUAL (equivalente ao File hash auto enrichment): calcular SHA256, consultar VT e registrar resultado", "owner": "analyst"},
                },
                {
                    "name": "task_revisar_headers_trace",
                    "action": "task.create",
                    "input": {"title": "Revisar headers, message trace, sender, reply-to e autenticacao do dominio", "owner": "analyst"},
                },
                {
                    "name": "task_validar_usuario",
                    "action": "task.create",
                    "input": {"title": "Validar com o usuario todas as acoes realizadas e seus horarios aproximados", "owner": "analyst"},
                },
                {
                    "name": "task_validar_escopo",
                    "action": "task.create",
                    "input": {"title": "Confirmar quem recebeu, abriu, clicou, respondeu ou executou payload", "owner": "analyst"},
                },
                {
                    "name": "task_revisar_evidencias",
                    "action": "task.create",
                    "input": {"title": "Revisar IOCs extraidos, enriquecimentos manuais e timeline tecnica do incidente", "owner": "analyst"},
                },
                {
                    "name": "task_classificar_ramo",
                    "action": "task.create",
                    "input": {"title": "CLASSIFICACAO DE RAMO: escolher credential-compromise, malware-suspected, bec ou mailbox-compromise", "owner": "analyst"},
                },
                {
                    "name": "task_contencao_credencial_manual",
                    "action": "task.create",
                    "input": {"title": "CONTENCAO MANUAL (credential): resetar senha, revogar sessoes, revisar MFA/OAuth e sinais de persistencia na mailbox", "owner": "soclead"},
                },
                {
                    "name": "task_contencao_malware_manual",
                    "action": "task.create",
                    "input": {"title": "CONTENCAO MANUAL (malware): isolar endpoint, coletar hash/processos, bloquear IOCs e remover email malicioso das caixas", "owner": "soclead"},
                },
                {
                    "name": "task_contencao_bec_manual",
                    "action": "task.create",
                    "input": {"title": "CONTENCAO MANUAL (BEC): acionar financeiro/banco, validar beneficiario fora de banda e preservar comprovantes/thread", "owner": "soclead"},
                },
                {
                    "name": "task_contencao_mailbox_manual",
                    "action": "task.create",
                    "input": {"title": "CONTENCAO MANUAL (mailbox compromise): reset/revoke, remover forwarding/rules, revisar sent items e consentimentos", "owner": "soclead"},
                },
                {
                    "name": "task_encaminhar_recovery",
                    "action": "task.create",
                    "input": {"title": "RECOVERY MANUAL: executar checklist de recuperacao e encerramento apos concluir a contencao", "owner": "analyst"},
                },
                {
                    "name": "task_documentar_decisao",
                    "action": "task.create",
                    "input": {"title": "Documentar severidade, ramo do incidente e proximos passos na timeline", "owner": "analyst"},
                },
                {
                    "name": "encerrar",
                    "action": "incident.add_note",
                    "input": {"message": "Fluxo manual espelho de phishing concluido."},
                },
            ],
            "on_error": "continue",
        }

        malware_phishing_dsl = {
            "name": "Malware phishing containment",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["phishing"], "any_label": ["malware", "malware-suspected", "attachment-execution"]},
                },
                {
                    "event": "incident.updated",
                    "filters": {
                        "labels": ["phishing"],
                        "any_label": ["malware", "malware-suspected", "attachment-execution"],
                        "changed_fields": ["labels"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "set_in_progress",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Tratamento de malware phishing iniciado"},
                },
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Ramo de phishing com suspeita de malware ativado."}},
                {"name": "ajustar_impacto", "action": "incident.update_impact", "input": {"severity": "HIGH", "risk_score": 75, "business_unit": "Endpoint"}},
                {"name": "rotular_fluxo", "action": "incident.add_labels", "input": {"labels": ["endpoint-response", "ioc-blocking"]}},
                {"name": "isolar_endpoint", "action": "task.create", "input": {"title": "Isolar o endpoint afetado e preservar a evidencia local", "owner": "soclead"}},
                {"name": "coletar_hashes", "action": "task.create", "input": {"title": "Coletar hash, nome do arquivo, processo e arvore de execucao do payload", "owner": "analyst"}},
                {"name": "bloquear_iocs", "action": "task.create", "input": {"title": "Bloquear URL, hash e dominio nos controles disponiveis", "owner": "analyst"}},
                {"name": "remover_email", "action": "task.create", "input": {"title": "Remover a mensagem maliciosa das caixas afetadas", "owner": "analyst"}},
                {
                    "name": "comunicar_endpoint",
                    "action": "communication.log",
                    "input": {"channel": "internal", "recipient_team": "EDR", "message": "Possivel malware entregue por phishing; avaliar isolamento e analise do endpoint."},
                },
            ],
            "on_error": "continue",
        }

        bec_financial_dsl = {
            "name": "BEC financial response",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["phishing"], "any_label": ["bec", "finance-fraud", "invoice-fraud", "gift-card"]},
                },
                {
                    "event": "incident.updated",
                    "filters": {
                        "labels": ["phishing"],
                        "any_label": ["bec", "finance-fraud", "invoice-fraud", "gift-card"],
                        "changed_fields": ["labels"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "set_in_progress",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Tratamento de BEC iniciado"},
                },
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Ramo de BEC com potencial impacto financeiro ativado."}},
                {"name": "ajustar_impacto", "action": "incident.update_impact", "input": {"severity": "CRITICAL", "risk_score": 95, "business_unit": "Financeiro"}},
                {"name": "rotular_fluxo", "action": "incident.add_labels", "input": {"labels": ["finance-response", "executive-visibility"]}},
                {"name": "acionar_financeiro", "action": "task.create", "input": {"title": "Acionar financeiro e banco imediatamente para recall, freeze ou rastreio da transferencia", "owner": "soclead"}},
                {"name": "validar_beneficiario", "action": "task.create", "input": {"title": "Validar mudanca bancaria, invoice ou pedido executivo por canal fora do email", "owner": "analyst"}},
                {"name": "preservar_documentos", "action": "task.create", "input": {"title": "Preservar invoice, thread de email, comprovantes e cronologia da fraude", "owner": "analyst"}},
                {"name": "escalar_executivo", "action": "incident.escalate", "input": {"level": "executive", "targets": ["SOC Lead", "Financeiro", "Juridico"]}},
                {
                    "name": "comunicar_financeiro",
                    "action": "communication.log",
                    "input": {"channel": "internal", "recipient_team": "Financeiro", "message": "Possivel BEC em andamento; suspender pagamentos e validar qualquer mudanca bancaria fora de banda."},
                },
            ],
            "on_error": "continue",
        }

        mailbox_compromise_dsl = {
            "name": "Mailbox compromise response",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["phishing"], "any_label": ["mailbox-compromise", "account-compromise", "thread-hijack"]},
                },
                {
                    "event": "incident.updated",
                    "filters": {
                        "labels": ["phishing"],
                        "any_label": ["mailbox-compromise", "account-compromise", "thread-hijack"],
                        "changed_fields": ["labels"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "set_in_progress",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Tratamento de mailbox compromise iniciado"},
                },
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Ramo de conta de email comprometida ativado."}},
                {"name": "ajustar_impacto", "action": "incident.update_impact", "input": {"severity": "HIGH", "risk_score": 85, "business_unit": "Messaging"}},
                {"name": "rotular_fluxo", "action": "incident.add_labels", "input": {"labels": ["mailbox-response", "identity-response"]}},
                {"name": "resetar_revoke", "action": "task.create", "input": {"title": "Desabilitar ou resetar a conta e revogar todas as sessoes ativas", "owner": "soclead"}},
                {"name": "remover_persistencia", "action": "task.create", "input": {"title": "Remover inbox rules, forwarding externo, delegacoes e transport rules anormais", "owner": "analyst"}},
                {"name": "revisar_sent_items", "action": "task.create", "input": {"title": "Revisar mensagens enviadas, destinatarios externos e possivel thread hijacking", "owner": "analyst"}},
                {"name": "revisar_oauth", "action": "task.create", "input": {"title": "Revisar app consent, roles privilegiados e apps com acesso a mailbox", "owner": "analyst"}},
                {
                    "name": "comunicar_m365",
                    "action": "communication.log",
                    "input": {"channel": "internal", "recipient_team": "M365/IAM", "message": "Possivel comprometimento de caixa de email; revisar sessoes, rules, forwarding, delegacoes e consentimentos."},
                },
            ],
            "on_error": "continue",
        }

        bec_manual_dsl = {
            "name": "BEC manual checklist",
            "type": "incident",
            "mode": "manual",
            "filters": [{"target": "incident", "conditions": {"labels": ["phishing"], "any_label": ["bec", "finance-fraud", "invoice-fraud", "gift-card"]}}],
            "steps": [
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Checklist manual de BEC iniciado."}},
                {"name": "validar_pagamentos", "action": "task.create", "input": {"title": "Confirmar pagamentos pendentes, recall com o banco e validacao do beneficiario", "owner": "soclead"}},
                {"name": "preservar_thread", "action": "task.create", "input": {"title": "Preservar invoice, thread comprometida, anexos e mensagens de alteracao bancaria", "owner": "analyst"}},
                {"name": "acionar_juridico", "action": "task.create", "input": {"title": "Acionar juridico/compliance e registrar necessidade de notificacao externa", "owner": "analyst"}},
                {"name": "registrar_fim", "action": "incident.add_note", "input": {"message": "Checklist manual de BEC concluido."}},
            ],
            "on_error": "continue",
        }

        mailbox_manual_dsl = {
            "name": "Mailbox compromise manual checklist",
            "type": "incident",
            "mode": "manual",
            "filters": [{"target": "incident", "conditions": {"labels": ["phishing"], "any_label": ["mailbox-compromise", "account-compromise", "thread-hijack"]}}],
            "steps": [
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Checklist manual de conta comprometida iniciado."}},
                {"name": "auditoria_mailbox", "action": "task.create", "input": {"title": "Revisar audit logs da mailbox, sent items e destinatarios externos apos o takeover", "owner": "analyst"}},
                {"name": "confirmar_cleanup", "action": "task.create", "input": {"title": "Confirmar remocao de rules, forwarding, delegacoes, app consent e roles indevidos", "owner": "analyst"}},
                {"name": "hunting_retroativo", "action": "task.create", "input": {"title": "Fazer hunting retroativo por IPs, URLs, regras e sign-ins correlatos", "owner": "analyst"}},
                {"name": "registrar_fim", "action": "incident.add_note", "input": {"message": "Checklist manual de conta comprometida concluido."}},
            ],
            "on_error": "continue",
        }

        recovery_closure_dsl = {
            "name": "Phishing recovery and closure",
            "type": "incident",
            "mode": "manual",
            "filters": [{"target": "incident", "conditions": {"labels": ["phishing"], "status": ["CONTAINED", "RESOLVED"]}}],
            "steps": [
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Checklist de recuperacao e encerramento iniciado."}},
                {"name": "validar_recuperacao", "action": "task.create", "input": {"title": "Validar que conta, mailbox, endpoint e mensagens remanescentes foram limpos", "owner": "analyst"}},
                {"name": "monitorar_pos_incidente", "action": "task.create", "input": {"title": "Monitorar sign-ins, envio de email e criacao de regras por 7 a 14 dias", "owner": "analyst"}},
                {"name": "comunicacao_final", "action": "task.create", "input": {"title": "Comunicar usuario afetado, gestor e registrar resumo executivo final", "owner": "analyst"}},
                {"name": "lessons_learned", "action": "task.create", "input": {"title": "Registrar licoes aprendidas e melhorias obrigatorias pos-incidente", "owner": "soclead"}},
                {"name": "registrar_fim", "action": "incident.add_note", "input": {"message": "Checklist de recuperacao e encerramento concluido."}},
            ],
            "on_error": "continue",
        }

        auto_artifact_ip_dsl = {
            "name": "IP auto enrichment",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [{"event": "artifact.created", "filters": {"type": ["IP"]}}],
            "steps": [
                {
                    "name": "consultar_vt",
                    "action": "virustotal_config.ip_lookup",
                    "input": {"ip": "{{artifact.value}}"},
                },
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "ip",
                                "indicator": "{{artifact.value}}",
                                "lookup": "{{results.consultar_vt}}",
                                "reputation": "{{results.consultar_vt.reputation|default:'unknown'}}",
                                "stats": "{{results.consultar_vt.stats}}",
                                "asn": "{{results.consultar_vt.asn|default:'sem_asn'}}",
                            }
                        }
                    },
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
                {
                    "name": "registrar_timeline",
                    "action": "incident.add_note",
                    "input": {
                        "message": (
                            "IP {{artifact.value}} consultado no VirusTotal via conector HTTP "
                            "(rep={{results.consultar_vt.reputation|default:'unknown'}})."
                        )
                    },
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
            ],
            "on_error": "continue",
        }

        email_auto_dsl = {
            "name": "Email evidence extraction",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [{"event": "artifact.created", "filters": {"type": ["EMAIL"]}}],
            "steps": [
                {
                    "name": "task_attach_raw_email",
                    "action": "task.create",
                    "input": {"title": "Anexar a mensagem bruta .eml ao artefato EMAIL e repetir a extracao automatica", "owner": "analyst"},
                    "when": {"left": "{{artifact.attributes.email_raw}}", "exists": False},
                },
                {"name": "parse_headers", "action": "artifact.parse_email_headers", "input": {}, "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True}},
                {"name": "extract_links", "action": "artifact.extract_links", "input": {}, "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True}},
                {"name": "extract_attachments", "action": "artifact.extract_attachments_metadata", "input": {}, "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True}},
                {"name": "extract_iocs", "action": "artifact.extract_iocs_from_email", "input": {}, "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True}},
                {"name": "label_parsed", "action": "incident.add_labels", "input": {"labels": ["email-evidence-parsed"]}, "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True}},
                {
                    "name": "register_summary",
                    "action": "incident.add_note",
                    "input": {
                        "message": "Email analisado automaticamente: assunto='{{results.parse_headers.headers.subject|default:\"(sem assunto)\"}}' remetente='{{results.parse_headers.headers.from|default:\"(sem remetente)\"}}'."
                    },
                    "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True},
                },
                {
                    "name": "task_review_iocs",
                    "action": "task.create",
                    "input": {"title": "Revisar links, dominios, IPs e anexos extraidos do email e criar artefatos relevantes", "owner": "analyst"},
                    "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True},
                },
                {
                    "name": "task_classify_branch",
                    "action": "task.create",
                    "input": {"title": "Classificar o tipo de incidente de email e acionar o playbook de tratamento adequado", "owner": "analyst"},
                    "when": {"left": "{{artifact.attributes.email_raw}}", "exists": True},
                },
            ],
            "on_error": "continue",
        }

        auto_artifact_domain_dsl = {
            "name": "Domain auto enrichment",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [{"event": "artifact.created", "filters": {"type": ["DOMAIN"]}}],
            "steps": [
                {"name": "consultar_vt", "action": "virustotal_config.domain_lookup", "input": {"domain": "{{artifact.value}}"}},
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "domain",
                                "indicator": "{{artifact.value}}",
                                "lookup": "{{results.consultar_vt}}",
                                "reputation": "{{results.consultar_vt.reputation|default:'unknown'}}",
                                "stats": "{{results.consultar_vt.stats}}",
                                "registrar": "{{results.consultar_vt.registrar|default:'desconhecido'}}",
                            }
                        }
                    },
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
                {
                    "name": "registrar_timeline",
                    "action": "incident.add_note",
                    "input": {"message": "Dominio {{artifact.value}} enriquecido automaticamente no VirusTotal (rep={{results.consultar_vt.reputation|default:'unknown'}})."},
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
            ],
            "on_error": "continue",
        }

        auto_artifact_url_dsl = {
            "name": "URL auto enrichment",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [{"event": "artifact.created", "filters": {"type": ["URL"]}}],
            "steps": [
                {"name": "submeter_vt", "action": "virustotal_config.url_submit", "input": {"url": "{{artifact.value}}"}},
                {
                    "name": "consultar_vt",
                    "action": "virustotal_config.url_report",
                    "input": {"url_id": "{{results.submeter_vt.analysis_id}}"},
                    "when": {"left": "{{results.submeter_vt.analysis_id}}", "exists": True},
                },
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "url",
                                "indicator": "{{artifact.value}}",
                                "submission": "{{results.submeter_vt}}",
                                "lookup": "{{results.consultar_vt}}",
                                "reputation": "{{results.consultar_vt.reputation|default:'unknown'}}",
                                "stats": "{{results.consultar_vt.stats}}",
                                "categories": "{{results.consultar_vt.categories}}",
                            }
                        }
                    },
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
                {
                    "name": "registrar_timeline",
                    "action": "incident.add_note",
                    "input": {"message": "URL {{artifact.value}} enriquecida automaticamente no VirusTotal (rep={{results.consultar_vt.reputation|default:'unknown'}})."},
                    "when": {"left": "{{results.consultar_vt}}", "exists": True},
                },
            ],
            "on_error": "continue",
        }

        auto_artifact_file_dsl = {
            "name": "File hash auto enrichment",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [{"event": "artifact.created", "filters": {"type": ["FILE"]}}],
            "steps": [
                {
                    "name": "task_missing_hash",
                    "action": "task.create",
                    "input": {"title": "Calcular ou confirmar o SHA256 do arquivo antes do enrichment automatico", "owner": "analyst"},
                    "when": {"left": "{{artifact_instance.sha256}}", "exists": False},
                },
                {"name": "consultar_resultado", "action": "virustotal_config.file_hash_report", "input": {"hash": "{{artifact_instance.sha256}}"}, "when": {"left": "{{artifact_instance.sha256}}", "exists": True}},
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "file",
                                "indicator": "{{artifact_instance.sha256}}",
                                "lookup": "{{results.consultar_resultado}}",
                                "reputation": "{{results.consultar_resultado.reputation|default:0}}",
                                "stats": "{{results.consultar_resultado.stats}}",
                                "meaningful_name": "{{results.consultar_resultado.meaningful_name|default:'sem_nome'}}",
                            }
                        }
                    },
                    "when": {
                        "all": [
                            {"left": "{{artifact_instance.sha256}}", "exists": True},
                            {"left": "{{results.consultar_resultado}}", "exists": True},
                        ]
                    },
                },
                {
                    "name": "registrar_timeline",
                    "action": "incident.add_note",
                    "input": {"message": "Hash {{artifact_instance.sha256}} enriquecido automaticamente no VirusTotal (rep={{results.consultar_resultado.reputation|default:0}})."},
                    "when": {
                        "all": [
                            {"left": "{{artifact_instance.sha256}}", "exists": True},
                            {"left": "{{results.consultar_resultado}}", "exists": True},
                        ]
                    },
                },
            ],
            "on_error": "continue",
        }

        email_manual_dsl = {
            "name": "Email manual review",
            "type": "artifact",
            "mode": "manual",
            "filters": [{"target": "artifact", "conditions": {"type": ["EMAIL"]}}],
            "steps": [
                {"name": "registrar_inicio", "action": "incident.add_note", "input": {"message": "Checklist manual de email iniciado."}},
                {"name": "parse_headers", "action": "artifact.parse_email_headers", "input": {}},
                {"name": "extract_links", "action": "artifact.extract_links", "input": {}},
                {"name": "extract_attachments", "action": "artifact.extract_attachments_metadata", "input": {}},
                {"name": "extract_iocs", "action": "artifact.extract_iocs_from_email", "input": {}},
                {"name": "task_review_output", "action": "task.create", "input": {"title": "Revisar saida do parse de email e promover os IOCs relevantes a artefatos do incidente", "owner": "analyst"}},
                {"name": "registrar_fim", "action": "incident.add_note", "input": {"message": "Checklist manual de email concluido."}},
            ],
            "on_error": "continue",
        }

        manual_artifact_domain_dsl = {
            "name": "Domain manual review",
            "description": "Checklist manual para dominios suspeitos.",
            "type": "artifact",
            "mode": "manual",
            "filters": [{"target": "artifact", "conditions": {"type": ["DOMAIN"]}}],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual de dominio iniciado."},
                },
                {
                    "name": "consultar_vt",
                    "action": "virustotal_config.domain_lookup",
                    "input": {"domain": "{{artifact.value}}"},
                },
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "domain",
                                "indicator": "{{artifact.value}}",
                                "lookup": "{{results.consultar_vt}}",
                                "reputation": "{{results.consultar_vt.reputation|default:'unknown'}}",
                                "stats": "{{results.consultar_vt.stats}}",
                                "registrar": "{{results.consultar_vt.registrar|default:'desconhecido'}}",
                            }
                        }
                    },
                },
                {
                    "name": "marcar_conclusao",
                    "action": "incident.add_note",
                    "input": {
                        "message": (
                            "Checklist manual de dominio concluido "
                            "(rep={{results.consultar_vt.reputation|default:'unknown'}})."
                        )
                    },
                },
            ],
            "on_error": "continue",
        }

        manual_artifact_url_dsl = {
            "name": "URL manual review",
            "description": "Checklist manual para URLs suspeitas usando os conectores HTTP do VirusTotal.",
            "type": "artifact",
            "mode": "manual",
            "filters": [{"target": "artifact", "conditions": {"type": ["URL"]}}],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual de URL iniciado."},
                },
                {
                    "name": "submeter_vt",
                    "action": "virustotal_config.url_submit",
                    "input": {"url": "{{artifact.value}}"},
                },
                {
                    "name": "consultar_vt",
                    "action": "virustotal_config.url_report",
                    "input": {"url_id": "{{results.submeter_vt.analysis_id}}"},
                },
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "url",
                                "indicator": "{{artifact.value}}",
                                "submission": "{{results.submeter_vt}}",
                                "lookup": "{{results.consultar_vt}}",
                                "reputation": "{{results.consultar_vt.reputation|default:'unknown'}}",
                                "stats": "{{results.consultar_vt.stats}}",
                                "categories": "{{results.consultar_vt.categories}}",
                            }
                        }
                    },
                },
                {
                    "name": "registrar_conclusao",
                    "action": "incident.add_note",
                    "input": {
                        "message": (
                            "Checklist manual de URL concluido "
                            "(rep={{results.consultar_vt.reputation|default:'unknown'}})."
                        )
                    },
                },
            ],
            "on_error": "continue",
        }

        manual_artifact_file_dsl = {
            "name": "File malware triage",
            "description": "Checklist manual para consulta de hash de arquivo no VirusTotal via conector HTTP.",
            "type": "artifact",
            "mode": "manual",
            "filters": [{"target": "artifact", "conditions": {"type": ["FILE"]}}],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Fluxo manual de analise de arquivo iniciado."},
                },
                {
                    "name": "consultar_resultado",
                    "action": "virustotal_config.file_hash_report",
                    "input": {"hash": "{{artifact_instance.sha256}}"},
                },
                {
                    "name": "persistir_vt",
                    "action": "artifact.update_attributes",
                    "input": {
                        "attributes": {
                            "virustotal": {
                                "source": "http-connector",
                                "indicator_type": "file",
                                "indicator": "{{artifact_instance.sha256}}",
                                "lookup": "{{results.consultar_resultado}}",
                                "reputation": "{{results.consultar_resultado.reputation|default:0}}",
                                "stats": "{{results.consultar_resultado.stats}}",
                                "meaningful_name": "{{results.consultar_resultado.meaningful_name|default:'sem_nome'}}",
                            }
                        }
                    },
                },
                {
                    "name": "registrar_conclusao",
                    "action": "incident.add_note",
                    "input": {
                        "message": (
                            "Checklist manual de arquivo concluido "
                            "(rep={{results.consultar_resultado.reputation|default:0}})."
                        )
                    },
                },
            ],
            "on_error": "continue",
        }

        def upsert_playbook(*, name: str, category: str, description: str, dsl: dict):
            playbook, created = Playbook.objects.get_or_create(
                name=name,
                defaults={
                    "category": category,
                    "description": description,
                    "dsl": dsl,
                    "enabled": True,
                    "created_by": lead,
                },
            )
            if not created:
                playbook.category = category
                playbook.description = description
                playbook.dsl = dsl
                playbook.enabled = True
                if not playbook.created_by:
                    playbook.created_by = lead
                playbook.save()
            self.stdout.write(f" - Playbook '{name}'")

        Playbook.objects.filter(name="Credential brute-force response").delete()

        for playbook_payload in [
            {"name": "Phishing triage", "category": "Tratamento - Phishing", "description": "Triagem inicial de incidentes de phishing com tarefas para coleta e classificacao.", "dsl": phishing_dsl},
            {"name": "Credential phishing containment", "category": "Tratamento - Phishing", "description": "Contencao inicial para phishing com roubo de credenciais.", "dsl": brute_force_dsl},
            {"name": "Malware phishing containment", "category": "Tratamento - Phishing", "description": "Contencao inicial para phishing com anexo ou payload suspeito.", "dsl": malware_phishing_dsl},
            {"name": "BEC financial response", "category": "Tratamento - Phishing", "description": "Resposta inicial para BEC com risco financeiro.", "dsl": bec_financial_dsl},
            {"name": "Mailbox compromise response", "category": "Tratamento - Phishing", "description": "Resposta inicial para conta de email comprometida ou thread hijack.", "dsl": mailbox_compromise_dsl},
            {"name": "Phishing manual checklist", "category": "Tratamento - Phishing", "description": "Fluxo manual espelho das automacoes de phishing, com tarefas equivalentes para triagem, enrichment e contencao.", "dsl": manual_phishing_dsl},
            {"name": "BEC manual checklist", "category": "Tratamento - Phishing", "description": "Checklist manual complementar para fraude financeira/BEC.", "dsl": bec_manual_dsl},
            {"name": "Mailbox compromise manual checklist", "category": "Tratamento - Phishing", "description": "Checklist manual complementar para erradicacao de conta comprometida.", "dsl": mailbox_manual_dsl},
            {"name": "Phishing recovery and closure", "category": "Tratamento - Phishing", "description": "Checklist de recuperacao, monitoramento e encerramento para phishing.", "dsl": recovery_closure_dsl},
            {"name": "Email evidence extraction", "category": "Auxiliar - Geral", "description": "Parse automatico de email bruto e extracao de IOCs reaproveitavel em qualquer incidente.", "dsl": email_auto_dsl},
            {"name": "Domain auto enrichment", "category": "Auxiliar - Geral", "description": "Enriquecimento automatico de dominios via VirusTotal para qualquer incidente.", "dsl": auto_artifact_domain_dsl},
            {"name": "IP auto enrichment", "category": "Auxiliar - Geral", "description": "Enriquecimento automatico de IPs via VirusTotal para qualquer incidente.", "dsl": auto_artifact_ip_dsl},
            {"name": "URL auto enrichment", "category": "Auxiliar - Geral", "description": "Enriquecimento automatico de URLs via VirusTotal para qualquer incidente.", "dsl": auto_artifact_url_dsl},
            {"name": "File hash auto enrichment", "category": "Auxiliar - Geral", "description": "Enriquecimento automatico de hashes de arquivo via VirusTotal para qualquer incidente.", "dsl": auto_artifact_file_dsl},
            {"name": "Email manual review", "category": "Auxiliar - Geral", "description": "Checklist manual para revisao ou reprocessamento de evidencias de email.", "dsl": email_manual_dsl},
            {"name": "Domain manual review", "category": "Auxiliar - Geral", "description": "Checklist manual para dominios suspeitos.", "dsl": manual_artifact_domain_dsl},
            {"name": "URL manual review", "category": "Auxiliar - Geral", "description": "Checklist manual para URLs suspeitas usando os conectores HTTP do VirusTotal.", "dsl": manual_artifact_url_dsl},
            {"name": "File malware triage", "category": "Auxiliar - Geral", "description": "Checklist manual para consulta de hash de arquivo no VirusTotal via conector HTTP.", "dsl": manual_artifact_file_dsl},
        ]:
            normalized_dsl = self._apply_manual_treatment_guard_to_automatic(playbook_payload["dsl"])
            upsert_playbook(
                name=playbook_payload["name"],
                category=playbook_payload["category"],
                description=playbook_payload["description"],
                dsl=normalized_dsl,
            )

        if not structures_only:
            self._seed_incidents(admin=admin, lead=lead, analyst=analyst)
            self.stdout.write(self.style.SUCCESS("Demo data pronta."))
        else:
            self.stdout.write(self.style.SUCCESS("Estruturas demo prontas."))

