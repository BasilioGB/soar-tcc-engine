from __future__ import annotations

import os

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import User
from incidents.models import Artifact, Incident, TimelineEntry
from incidents.services import add_artifact_link, update_artifact_attributes
from playbooks.models import Playbook


class Command(BaseCommand):
    help = "Create demo data for basilio-soar"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Permite executar o seed mesmo sem ALLOW_DEMO_SEED=1.",
        )

    @staticmethod
    def _seed_allowed(force: bool) -> bool:
        return force or os.getenv("ALLOW_DEMO_SEED", "").strip() == "1"

    @transaction.atomic
    def handle(self, *args, **options):
        if not self._seed_allowed(force=bool(options.get("force"))):
            raise CommandError(
                "Execucao bloqueada. Defina ALLOW_DEMO_SEED=1 ou execute com --force."
            )
        self.stdout.write(self.style.MIGRATE_HEADING("Seeding demo data"))

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

        phishing_dsl = {
            "name": "Phishing triage",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["phishing"]}
                }
            ],
            "steps": [
                {
                    "name": "log_start",
                    "action": "incident.add_note",
                    "input": {"message": "Playbook de phishing iniciado automaticamente"},
                },
                {
                    "name": "set_status",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Playbook de phishing"},
                },
                {
                    "name": "tag_auto",
                    "action": "incident.add_labels",
                    "input": {"labels": ["auto-playbook", "phishing-triage"]},
                },
                {
                    "name": "enrich_domain",
                    "action": "virustotal.domain_report",
                    "input": {"artifact_type": "DOMAIN"},
                },
                {
                    "name": "enrich_url",
                    "action": "virustotal.url_report",
                    "input": {"artifact_type": "URL"},
                },
                {
                    "name": "task_review_headers",
                    "action": "task.create",
                    "input": {"title": "Revisar cabecalhos do email suspeito", "owner": "analyst"},
                },
                {
                    "name": "internal_comm",
                    "action": "communication.log",
                    "input": {"channel": "internal", "message": "Playbook registrou phishing; aguardando analise."},
                },
                {"name": "final_tag", "action": "incident.add_label", "input": {"label": "triaged"}},
            ],
            "on_error": "continue",
        }

        brute_force_dsl = {
            "name": "Credential brute-force response",
            "type": "incident",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "incident.created",
                    "filters": {"labels": ["credential"]}
                }
            ],
            "steps": [
                {
                    "name": "log_start",
                    "action": "incident.add_note",
                    "input": {"message": "Playbook de brute force iniciado automaticamente"},
                },
                {
                    "name": "status_in_progress",
                    "action": "incident.update_status",
                    "input": {"status": "IN_PROGRESS", "reason": "Resposta a brute force"},
                },
                {
                    "name": "add_labels",
                    "action": "incident.add_labels",
                    "input": {"labels": ["auto-playbook", "credential-investigation"]},
                },
                {
                    "name": "task_disable_account",
                    "action": "task.create",
                    "input": {"title": "Suspender conta afetada", "owner": "soclead"},
                },
                {
                    "name": "task_review_logs",
                    "action": "task.create",
                    "input": {"title": "Revisar logs de autenticacao", "owner": "analyst"},
                },
                {
                    "name": "vt_ip_lookup",
                    "action": "virustotal.ip_report",
                    "input": {"artifact_type": "IP"},
                },
                {
                    "name": "escalate",
                    "action": "incident.escalate",
                    "input": {"level": "tier2", "targets": ["SOC lead", "Infra"]},
                },
                {
                    "name": "internal_comm",
                    "action": "communication.log",
                    "input": {
                        "channel": "internal",
                        "recipient_team": "SOC",
                        "message": "Investigacao de brute force em andamento.",
                    },
                },
                {
                    "name": "final_note",
                    "action": "incident.add_note",
                    "input": {"message": "Playbook finalizado; acompanhar tarefas manuais."},
                },
            ],
            "on_error": "continue",
        }

        manual_phishing_dsl = {
            "name": "Phishing manual checklist",
            "type": "incident",
            "mode": "manual",
            "filters": [
                {
                    "target": "incident",
                    "conditions": {
                        "labels": ["phishing"],
                        "severity": ["MEDIUM", "HIGH", "CRITICAL"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual iniciado"},
                },
                {
                    "name": "abrir_followup",
                    "action": "task.create",
                    "input": {"title": "Revisar cabecalhos", "owner": "analyst"},
                },
                {
                    "name": "encerrar",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual concluido"},
                },
            ],
            "on_error": "continue",
        }

        auto_artifact_ip_dsl = {
            "name": "IP auto enrichment",
            "description": "Enriquece automaticamente IPs adicionados ao incidente.",
            "type": "artifact",
            "mode": "automatic",
            "triggers": [
                {
                    "event": "artifact.created",
                    "filters": {"type": ["IP"]},
                }
            ],
            "steps": [
                {
                    "name": "consultar_vt",
                    "action": "virustotal.ip_report",
                    "input": {},
                },
                {
                    "name": "registrar_timeline",
                    "action": "incident.add_note",
                    "input": {"message": "Playbook automatico de IP executado."},
                },
            ],
            "on_error": "continue",
        }

        manual_artifact_domain_dsl = {
            "name": "Domain manual review",
            "description": "Checklist manual para dominios suspeitos.",
            "type": "artifact",
            "mode": "manual",
            "filters": [
                {
                    "target": "artifact",
                    "conditions": {
                        "type": ["DOMAIN"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual de dominio iniciado."},
                },
                {
                    "name": "consultar_vt",
                    "action": "virustotal.domain_report",
                    "input": {"artifact_type": "DOMAIN"},
                },
                {
                    "name": "marcar_conclusao",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual de dominio concluido."},
                },
            ],
            "on_error": "continue",
        }

        manual_artifact_file_dsl = {
            "name": "File malware triage",
            "description": "Checklist manual para arquivos suspeitos anexados a incidentes.",
            "type": "artifact",
            "mode": "manual",
            "filters": [
                {
                    "target": "artifact",
                    "conditions": {
                        "type": ["FILE"],
                    },
                }
            ],
            "steps": [
                {
                    "name": "registrar_inicio",
                    "action": "incident.add_note",
                    "input": {"message": "Fluxo manual de analise de arquivo iniciado."},
                },
                {
                    "name": "enviar_para_vt",
                    "action": "virustotal.file_upload",
                    "input": {},
                },
                {
                    "name": "consultar_resultado",
                    "action": "virustotal.file_report",
                    "input": {"artifact_type": "FILE"},
                },
                {
                    "name": "registrar_conclusao",
                    "action": "incident.add_note",
                    "input": {"message": "Checklist manual de arquivo concluido; revisar atributos do artefato."},
                },
            ],
            "on_error": "continue",
        }

        phish_playbook, created = Playbook.objects.get_or_create(
            name="Phishing triage",
            defaults={
                "description": "Fluxo basico para triagem de phishing",
                "dsl": phishing_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            phish_playbook.dsl = phishing_dsl
            phish_playbook.enabled = True
            if not phish_playbook.created_by:
                phish_playbook.created_by = lead
            phish_playbook.save()
        self.stdout.write(" - Playbook 'Phishing triage'")

        manual_phish_playbook, created = Playbook.objects.get_or_create(
            name="Phishing manual checklist",
            defaults={
                "description": "Checklist manual auxiliar para cenarios de phishing",
                "dsl": manual_phishing_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            manual_phish_playbook.dsl = manual_phishing_dsl
            manual_phish_playbook.enabled = True
            if not manual_phish_playbook.created_by:
                manual_phish_playbook.created_by = lead
            manual_phish_playbook.save()
        self.stdout.write(" - Playbook 'Phishing manual checklist'")

        brute_playbook, created = Playbook.objects.get_or_create(
            name="Credential brute-force response",
            defaults={
                "description": "Contencao e notificacao para tentativas de brute force",
                "dsl": brute_force_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            brute_playbook.dsl = brute_force_dsl
            brute_playbook.enabled = True
            if not brute_playbook.created_by:
                brute_playbook.created_by = lead
            brute_playbook.save()
        self.stdout.write(" - Playbook 'Credential brute-force response'")

        auto_ip_playbook, created = Playbook.objects.get_or_create(
            name="IP auto enrichment",
            defaults={
                "description": "Enriquecimento automatico de IPs via VirusTotal",
                "dsl": auto_artifact_ip_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            auto_ip_playbook.dsl = auto_artifact_ip_dsl
            auto_ip_playbook.enabled = True
            if not auto_ip_playbook.created_by:
                auto_ip_playbook.created_by = lead
            auto_ip_playbook.save()
        self.stdout.write(" - Playbook 'IP auto enrichment'")

        manual_domain_playbook, created = Playbook.objects.get_or_create(
            name="Domain manual review",
            defaults={
                "description": "Checklist manual para dominios associados a phishing",
                "dsl": manual_artifact_domain_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            manual_domain_playbook.dsl = manual_artifact_domain_dsl
            manual_domain_playbook.enabled = True
            if not manual_domain_playbook.created_by:
                manual_domain_playbook.created_by = lead
            manual_domain_playbook.save()
        self.stdout.write(" - Playbook 'Domain manual review'")

        manual_file_playbook, created = Playbook.objects.get_or_create(
            name="File malware triage",
            defaults={
                "description": "Checklist manual para anexos suspeitos via VirusTotal",
                "dsl": manual_artifact_file_dsl,
                "enabled": True,
                "created_by": lead,
            },
        )
        if not created:
            manual_file_playbook.dsl = manual_artifact_file_dsl
            manual_file_playbook.enabled = True
            if not manual_file_playbook.created_by:
                manual_file_playbook.created_by = lead
            manual_file_playbook.save()
        self.stdout.write(" - Playbook 'File malware triage'")

        incidents_seed = [
            {
                "title": "Email suspeito de phishing",
                "description": "Colaborador reportou email solicitando redefinicao de senha.",
                "severity": Incident.Severity.MEDIUM,
                "status": Incident.Status.IN_PROGRESS,
                "labels": ["phishing", "email"],
                "artifacts": [
                    {"type": Artifact.Type.EMAIL, "value": "phish@example.com"},
                    {"type": Artifact.Type.URL, "value": "http://malicious.example"},
                    {"type": Artifact.Type.DOMAIN, "value": "malicious.example"},
                ],
                "notes": [
                    "Email encaminhado pelo colaborador.",
                    "Solicitada analise do dominio suspeito.",
                ],
            },
            {
                "title": "Acesso nao autorizado",
                "description": "Alertas de login fora do horario para conta privilegiada.",
                "severity": Incident.Severity.HIGH,
                "status": Incident.Status.NEW,
                "labels": ["credential", "alert"],
                "artifacts": [
                    {"type": Artifact.Type.IP, "value": "203.0.113.45"},
                ],
                "notes": ["Investigacao inicial pendente."],
            },
        ]

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
                artifact_obj = add_artifact_link(
                    incident=incident,
                    value=artifact_payload["value"],
                    type_code=artifact_payload["type"],
                    actor=analyst,
                )
                if artifact_obj.type == Artifact.Type.DOMAIN:
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
                if artifact_obj.type == Artifact.Type.IP:
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

        self.stdout.write(self.style.SUCCESS("Demo data pronta."))

