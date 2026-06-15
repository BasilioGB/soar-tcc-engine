from __future__ import annotations

import os
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from accounts.models import User
from incidents.models import Incident
from integrations.models import IntegrationDefinition, IntegrationSecretRef
from playbooks.models import Execution, Playbook
from playbooks.services import get_manual_playbooks_for_incident, start_playbook_execution


class SeedDemoCommandHardeningTests(TestCase):
    def test_seed_demo_requires_opt_in(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", stdout=StringIO())

    def test_seed_demo_accepts_force_flag(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, stdout=StringIO())
        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(IntegrationSecretRef.objects.filter(name="VIRUSTOTAL_API_KEY").exists())
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="virustotal_config.domain_lookup").exists()
        )
        self.assertTrue(
            IntegrationDefinition.objects.filter(action_name="virustotal_config.url_report").exists()
        )
        self.assertTrue(Playbook.objects.filter(name="Credential phishing containment").exists())
        self.assertTrue(Playbook.objects.filter(name="Credential compromise manual checklist").exists())
        self.assertTrue(Playbook.objects.filter(name="Email evidence extraction").exists())
        self.assertTrue(Playbook.objects.filter(name="BEC financial response").exists())
        self.assertTrue(Playbook.objects.filter(name="IOC malicious infrastructure response").exists())
        self.assertTrue(Playbook.objects.filter(name="IOC malicious infrastructure manual checklist").exists())
        self.assertTrue(Playbook.objects.filter(name="Branching decision demo").exists())
        self.assertTrue(Playbook.objects.filter(name="Malware suspected manual checklist").exists())
        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(Playbook.objects.filter(name="Domain manual review").exists())
        self.assertTrue(Playbook.objects.filter(name="URL manual review").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo credential compromise - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo credential compromise - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo malware - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo malware - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo mailbox compromise - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo mailbox compromise - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - MANUAL").exists())
        manual_compare = Incident.objects.get(title="Comparativo phishing - MANUAL")
        self.assertIn("manual-treatment", manual_compare.labels)
        credential_auto_compare = Incident.objects.get(title="Comparativo credential compromise - AUTO")
        credential_manual_compare = Incident.objects.get(title="Comparativo credential compromise - MANUAL")
        self.assertEqual(
            set(credential_auto_compare.labels),
            {"phishing", "credential-compromise", "auto-treatment"},
        )
        self.assertEqual(
            set(credential_manual_compare.labels),
            {"phishing", "credential-compromise", "manual-treatment"},
        )
        self.assertEqual(credential_auto_compare.artifacts.count(), 4)
        self.assertEqual(credential_manual_compare.artifacts.count(), 4)
        credential_auto_ip = credential_auto_compare.artifacts.filter(type="IP").first()
        self.assertIsNotNone(credential_auto_ip)
        self.assertEqual((credential_auto_ip.attributes or {}).get("alert_id"), "SIM-CREDENTIAL-AUTO-001")
        credential_auto_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(credential_auto_compare)
        }
        credential_manual_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(credential_manual_compare)
        }
        self.assertNotIn("Credential compromise manual checklist", credential_auto_manual_names)
        self.assertIn("Credential compromise manual checklist", credential_manual_manual_names)
        malware_auto_compare = Incident.objects.get(title="Comparativo malware - AUTO")
        malware_manual_compare = Incident.objects.get(title="Comparativo malware - MANUAL")
        self.assertEqual(
            set(malware_auto_compare.labels),
            {"phishing", "malware-suspected", "auto-treatment"},
        )
        self.assertEqual(
            set(malware_manual_compare.labels),
            {"phishing", "malware-suspected", "manual-treatment"},
        )
        self.assertEqual(malware_auto_compare.artifacts.count(), 5)
        self.assertEqual(malware_manual_compare.artifacts.count(), 5)
        malware_auto_hash = malware_auto_compare.artifacts.filter(type="HASH").first()
        self.assertIsNotNone(malware_auto_hash)
        self.assertEqual((malware_auto_hash.attributes or {}).get("alert_id"), "SIM-MALWARE-AUTO-001")
        auto_available_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(malware_auto_compare)
        }
        manual_available_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(malware_manual_compare)
        }
        self.assertNotIn("Malware suspected manual checklist", auto_available_manual_names)
        self.assertIn("Malware suspected manual checklist", manual_available_manual_names)
        mailbox_auto_compare = Incident.objects.get(title="Comparativo mailbox compromise - AUTO")
        mailbox_manual_compare = Incident.objects.get(title="Comparativo mailbox compromise - MANUAL")
        self.assertEqual(
            set(mailbox_auto_compare.labels),
            {"phishing", "mailbox-compromise", "auto-treatment"},
        )
        self.assertEqual(
            set(mailbox_manual_compare.labels),
            {"phishing", "mailbox-compromise", "manual-treatment"},
        )
        self.assertEqual(mailbox_auto_compare.artifacts.count(), 4)
        self.assertEqual(mailbox_manual_compare.artifacts.count(), 4)
        mailbox_auto_ip = mailbox_auto_compare.artifacts.filter(type="IP").first()
        self.assertIsNotNone(mailbox_auto_ip)
        self.assertEqual((mailbox_auto_ip.attributes or {}).get("alert_id"), "SIM-MAILBOX-AUTO-001")
        mailbox_auto_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(mailbox_auto_compare)
        }
        mailbox_manual_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(mailbox_manual_compare)
        }
        self.assertNotIn("Mailbox compromise manual checklist", mailbox_auto_manual_names)
        self.assertIn("Mailbox compromise manual checklist", mailbox_manual_manual_names)
        ioc_auto_compare = Incident.objects.get(title="Comparativo IOC malicious infrastructure - AUTO")
        ioc_manual_compare = Incident.objects.get(title="Comparativo IOC malicious infrastructure - MANUAL")
        self.assertEqual(
            set(ioc_auto_compare.labels),
            {"ioc-malicious-infrastructure", "auto-treatment"},
        )
        self.assertEqual(
            set(ioc_manual_compare.labels),
            {"ioc-malicious-infrastructure", "manual-treatment"},
        )
        self.assertEqual(ioc_auto_compare.artifacts.count(), 4)
        self.assertEqual(ioc_manual_compare.artifacts.count(), 4)
        ioc_auto_ip = ioc_auto_compare.artifacts.filter(type="IP").first()
        self.assertIsNotNone(ioc_auto_ip)
        self.assertEqual((ioc_auto_ip.attributes or {}).get("alert_id"), "SIM-IOC-AUTO-001")
        ioc_auto_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(ioc_auto_compare)
        }
        ioc_manual_manual_names = {
            playbook.name for playbook in get_manual_playbooks_for_incident(ioc_manual_compare)
        }
        self.assertNotIn("IOC malicious infrastructure manual checklist", ioc_auto_manual_names)
        self.assertIn("IOC malicious infrastructure manual checklist", ioc_manual_manual_names)
        url_auto = Playbook.objects.get(name="URL auto enrichment")
        url_steps = {step["name"]: step for step in url_auto.dsl.get("steps", [])}
        self.assertEqual(
            url_steps["consultar_vt"].get("when"),
            {"left": "{{results.submeter_vt.analysis_id}}", "exists": True},
        )
        self.assertEqual(
            url_steps["persistir_vt"].get("when"),
            {"left": "{{results.consultar_vt}}", "exists": True},
        )
        domain_auto = Playbook.objects.get(name="Domain auto enrichment")
        domain_steps = {step["name"]: step for step in domain_auto.dsl.get("steps", [])}
        self.assertEqual(
            domain_steps["decidir_veredito_vt"].get("action"),
            "control.branch",
        )
        self.assertEqual(
            domain_steps["decidir_veredito_vt"].get("when"),
            {"left": "{{results.consultar_vt.stats}}", "exists": True},
        )
        branch_names = [
            branch.get("name")
            for branch in domain_steps["decidir_veredito_vt"].get("branches", [])
        ]
        self.assertEqual(branch_names, ["malicious", "suspicious"])
        malicious_branch = domain_steps["decidir_veredito_vt"]["branches"][0]
        malicious_step_names = [step.get("name") for step in malicious_branch.get("steps", [])]
        self.assertEqual(
            malicious_step_names,
            [
                "task_bloquear_dominio_malicioso",
                "rotular_dominio_malicioso",
                "registrar_decisao_maliciosa",
            ],
        )
        default_step_names = [
            step.get("name")
            for step in domain_steps["decidir_veredito_vt"].get("default", [])
        ]
        self.assertEqual(default_step_names, ["registrar_dominio_sem_deteccoes"])
        branch_playbooks = [
            (
                "Credential phishing containment",
                ["phishing", "credential-compromise"],
                None,
            ),
            (
                "Malware phishing containment",
                ["phishing"],
                ["malware", "malware-suspected", "attachment-execution"],
            ),
            (
                "BEC financial response",
                ["phishing"],
                ["bec", "finance-fraud", "invoice-fraud", "gift-card"],
            ),
            (
                "Mailbox compromise response",
                ["phishing"],
                ["mailbox-compromise", "account-compromise", "thread-hijack"],
            ),
            (
                "IOC malicious infrastructure response",
                ["ioc-malicious-infrastructure"],
                None,
            ),
        ]
        for playbook_name, expected_labels, expected_any_label in branch_playbooks:
            playbook = Playbook.objects.get(name=playbook_name)
            triggers = playbook.dsl.get("triggers", [])
            steps = playbook.dsl.get("steps", [])
            created_trigger = next(
                (trigger for trigger in triggers if trigger.get("event") == "incident.created"),
                None,
            )
            updated_trigger = next(
                (trigger for trigger in triggers if trigger.get("event") == "incident.updated"),
                None,
            )
            self.assertIsNotNone(created_trigger)
            self.assertIsNotNone(updated_trigger)
            self.assertEqual(
                updated_trigger.get("filters", {}).get("changed_fields"),
                ["labels"],
            )
            self.assertEqual(
                updated_trigger.get("filters", {}).get("labels"),
                expected_labels,
            )
            if expected_any_label is None:
                self.assertNotIn("any_label", updated_trigger.get("filters", {}))
            else:
                self.assertEqual(
                    updated_trigger.get("filters", {}).get("any_label"),
                    expected_any_label,
                )
            self.assertEqual(
                created_trigger.get("filters", {}).get("exclude_labels"),
                ["manual-treatment"],
            )
            self.assertEqual(
                updated_trigger.get("filters", {}).get("exclude_labels"),
                ["manual-treatment"],
            )
            self.assertGreater(len(steps), 0)
            self.assertEqual(steps[0].get("action"), "incident.update_status")
            self.assertEqual(steps[0].get("input", {}).get("status"), "IN_PROGRESS")

        credential_auto = Playbook.objects.get(name="Credential phishing containment")
        credential_auto_steps = {step["name"]: step for step in credential_auto.dsl.get("steps", [])}
        credential_auto_labels = set(credential_auto_steps["add_labels"].get("input", {}).get("labels", []))
        self.assertTrue(
            {
                "identity-response",
                "account-review",
                "session-revocation",
                "mfa-review",
                "oauth-review",
                "signin-review",
            }.issubset(credential_auto_labels)
        )
        credential_auto_task_titles = [
            step.get("input", {}).get("title", "")
            for step in credential_auto.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_credential_auto_fragments = [
            "Resetar senha e revogar",
            "Revisar metodos MFA",
            "Revisar sign-ins",
            "Revisar IPs de login suspeitos",
            "Revisar forwarding, inbox rules",
            "Monitorar sign-ins",
        ]
        for fragment in expected_credential_auto_fragments:
            self.assertTrue(
                any(fragment in title for title in credential_auto_task_titles),
                msg=f"Tarefa automatizada de credential ausente: {fragment}",
            )
        self.assertEqual(
            credential_auto_steps["escalate"].get("action"),
            "incident.escalate",
        )
        self.assertEqual(
            credential_auto_steps["internal_comm"].get("action"),
            "communication.log",
        )
        self.assertEqual(
            credential_auto_steps["registrar_automacao"].get("action"),
            "incident.add_note",
        )

        malware_auto = Playbook.objects.get(name="Malware phishing containment")
        malware_auto_steps = {step["name"]: step for step in malware_auto.dsl.get("steps", [])}
        self.assertIn(
            "malware-analysis",
            malware_auto_steps["rotular_fluxo"].get("input", {}).get("labels", []),
        )
        malware_auto_task_titles = [
            step.get("input", {}).get("title", "")
            for step in malware_auto.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_auto_fragments = [
            "Isolar o endpoint afetado",
            "Coletar hash",
            "Revisar resultados dos enriquecimentos automaticos",
            "Bloquear URL, hash e dominio",
            "Remover a mensagem maliciosa",
            "Executar hunting em endpoints",
        ]
        for fragment in expected_auto_fragments:
            self.assertTrue(
                any(fragment in title for title in malware_auto_task_titles),
                msg=f"Tarefa automatizada de malware ausente: {fragment}",
            )
        self.assertEqual(
            malware_auto_steps["comunicar_endpoint"].get("action"),
            "communication.log",
        )
        self.assertEqual(
            malware_auto_steps["registrar_automacao"].get("action"),
            "incident.add_note",
        )

        mailbox_auto = Playbook.objects.get(name="Mailbox compromise response")
        mailbox_auto_steps = {step["name"]: step for step in mailbox_auto.dsl.get("steps", [])}
        mailbox_auto_labels = set(mailbox_auto_steps["rotular_fluxo"].get("input", {}).get("labels", []))
        self.assertTrue(
            {
                "mailbox-response",
                "identity-response",
                "mailbox-persistence",
                "forwarding-review",
                "rules-review",
                "delegation-review",
                "thread-hijack-review",
                "oauth-review",
            }.issubset(mailbox_auto_labels)
        )
        mailbox_auto_task_titles = [
            step.get("input", {}).get("title", "")
            for step in mailbox_auto.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_mailbox_auto_fragments = [
            "Desabilitar ou resetar a conta",
            "Remover inbox rules",
            "Revisar mensagens enviadas",
            "Revisar app consent",
            "Identificar destinatarios internos e externos",
            "Monitorar sign-ins",
        ]
        for fragment in expected_mailbox_auto_fragments:
            self.assertTrue(
                any(fragment in title for title in mailbox_auto_task_titles),
                msg=f"Tarefa automatizada de mailbox ausente: {fragment}",
            )
        self.assertEqual(
            mailbox_auto_steps["comunicar_m365"].get("action"),
            "communication.log",
        )
        self.assertEqual(
            mailbox_auto_steps["registrar_automacao"].get("action"),
            "incident.add_note",
        )

        ioc_auto = Playbook.objects.get(name="IOC malicious infrastructure response")
        ioc_auto_steps = {step["name"]: step for step in ioc_auto.dsl.get("steps", [])}
        ioc_auto_labels = set(ioc_auto_steps["rotular_fluxo"].get("input", {}).get("labels", []))
        self.assertTrue(
            {
                "ioc-response",
                "threat-intel",
                "blocking-required",
                "infrastructure-review",
                "exposure-hunting",
            }.issubset(ioc_auto_labels)
        )
        ioc_auto_task_titles = [
            step.get("input", {}).get("title", "")
            for step in ioc_auto.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_ioc_auto_fragments = [
            "Validar reputacao e origem do IOC",
            "Revisar enriquecimentos automaticos",
            "Buscar trafego interno",
            "Correlacionar o IOC",
            "Bloquear IP, dominio, URL e hash",
        ]
        for fragment in expected_ioc_auto_fragments:
            self.assertTrue(
                any(fragment in title for title in ioc_auto_task_titles),
                msg=f"Tarefa automatizada de IOC ausente: {fragment}",
            )
        self.assertEqual(
            ioc_auto_steps["escalate"].get("action"),
            "incident.escalate",
        )
        self.assertEqual(
            ioc_auto_steps["comunicar_times"].get("action"),
            "communication.log",
        )
        self.assertEqual(
            ioc_auto_steps["registrar_automacao"].get("action"),
            "incident.add_note",
        )

        phishing_manual = Playbook.objects.get(name="Phishing manual checklist")
        manual_filters = phishing_manual.dsl.get("filters", [])
        self.assertGreater(len(manual_filters), 0)
        first_conditions = manual_filters[0].get("conditions", {})
        self.assertEqual(first_conditions.get("labels"), ["phishing"])
        self.assertEqual(first_conditions.get("any_label"), ["manual-treatment"])

        credential_manual = Playbook.objects.get(name="Credential compromise manual checklist")
        credential_manual_filters = credential_manual.dsl.get("filters", [])
        self.assertGreater(len(credential_manual_filters), 0)
        credential_manual_conditions = credential_manual_filters[0].get("conditions", {})
        self.assertEqual(
            credential_manual_conditions.get("labels"),
            ["phishing", "credential-compromise", "manual-treatment"],
        )
        credential_manual_task_titles = [
            step.get("input", {}).get("title", "")
            for step in credential_manual.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_credential_manual_fragments = [
            "Confirmar usuario afetado",
            "Resetar senha e revogar",
            "Revisar metodos MFA",
            "Revisar app consent",
            "Revisar sign-ins",
            "Consultar manualmente IPs de login",
            "Revisar forwarding, inbox rules",
            "Determinar escopo",
            "Monitorar sign-ins",
            "Encaminhar para recovery",
        ]
        for fragment in expected_credential_manual_fragments:
            self.assertTrue(
                any(fragment in title for title in credential_manual_task_titles),
                msg=f"Tarefa manual de credential ausente: {fragment}",
            )

        malware_manual = Playbook.objects.get(name="Malware suspected manual checklist")
        malware_manual_filters = malware_manual.dsl.get("filters", [])
        self.assertGreater(len(malware_manual_filters), 0)
        malware_manual_conditions = malware_manual_filters[0].get("conditions", {})
        self.assertEqual(malware_manual_conditions.get("labels"), ["phishing", "manual-treatment"])
        self.assertEqual(
            malware_manual_conditions.get("any_label"),
            ["malware", "malware-suspected", "attachment-execution"],
        )
        malware_manual_task_titles = [
            step.get("input", {}).get("title", "")
            for step in malware_manual.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_manual_fragments = [
            "Isolar o endpoint afetado",
            "Coletar SHA256",
            "Consultar manualmente o hash",
            "Consultar manualmente URL, dominio e IP",
            "Bloquear URL, hash e dominio",
            "Remover a mensagem maliciosa",
            "Executar hunting em endpoints",
            "Validar se houve execucao do payload",
            "Encaminhar para recovery",
        ]
        for fragment in expected_manual_fragments:
            self.assertTrue(
                any(fragment in title for title in malware_manual_task_titles),
                msg=f"Tarefa manual de malware ausente: {fragment}",
            )

        mailbox_manual = Playbook.objects.get(name="Mailbox compromise manual checklist")
        mailbox_manual_filters = mailbox_manual.dsl.get("filters", [])
        self.assertGreater(len(mailbox_manual_filters), 0)
        mailbox_manual_conditions = mailbox_manual_filters[0].get("conditions", {})
        self.assertEqual(mailbox_manual_conditions.get("labels"), ["phishing", "manual-treatment"])
        self.assertEqual(
            mailbox_manual_conditions.get("any_label"),
            ["mailbox-compromise", "account-compromise", "thread-hijack"],
        )
        mailbox_manual_task_titles = [
            step.get("input", {}).get("title", "")
            for step in mailbox_manual.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_mailbox_manual_fragments = [
            "Confirmar conta afetada",
            "Resetar a conta e revogar",
            "Remover inbox rules",
            "Revisar delegacoes",
            "Revisar sent items",
            "Revisar app consent",
            "Revisar audit logs da mailbox",
            "Identificar destinatarios internos e externos",
            "Fazer hunting retroativo",
            "Monitorar sign-ins",
            "Encaminhar para recovery",
        ]
        for fragment in expected_mailbox_manual_fragments:
            self.assertTrue(
                any(fragment in title for title in mailbox_manual_task_titles),
                msg=f"Tarefa manual de mailbox ausente: {fragment}",
            )

        ioc_manual = Playbook.objects.get(name="IOC malicious infrastructure manual checklist")
        ioc_manual_filters = ioc_manual.dsl.get("filters", [])
        self.assertGreater(len(ioc_manual_filters), 0)
        ioc_manual_conditions = ioc_manual_filters[0].get("conditions", {})
        self.assertEqual(
            ioc_manual_conditions.get("labels"),
            ["ioc-malicious-infrastructure", "manual-treatment"],
        )
        ioc_manual_task_titles = [
            step.get("input", {}).get("title", "")
            for step in ioc_manual.dsl.get("steps", [])
            if step.get("action") == "task.create"
        ]
        expected_ioc_manual_fragments = [
            "Identificar tipo do IOC",
            "Validar reputacao e origem do IOC",
            "Consultar manualmente IP, dominio, URL e hash",
            "Revisar DNS, proxy, firewall, EDR e SIEM",
            "Buscar hosts, usuarios e sistemas internos",
            "Correlacionar o IOC",
            "Bloquear IP, dominio, URL e hash",
            "Acionar Threat Intel",
            "Documentar reputacao",
            "Encaminhar para recovery",
        ]
        for fragment in expected_ioc_manual_fragments:
            self.assertTrue(
                any(fragment in title for title in ioc_manual_task_titles),
                msg=f"Tarefa manual de IOC ausente: {fragment}",
            )

        branching_demo = Playbook.objects.get(name="Branching decision demo")
        branching_filters = branching_demo.dsl.get("filters", [])
        self.assertGreater(len(branching_filters), 0)
        self.assertEqual(
            branching_filters[0].get("conditions", {}).get("labels"),
            ["branching-demo"],
        )
        branching_steps = {
            step.get("name"): step
            for step in branching_demo.dsl.get("steps", [])
        }
        self.assertEqual(
            branching_steps["decidir_caminho_severidade"].get("action"),
            "control.branch",
        )
        self.assertEqual(
            [
                branch.get("name")
                for branch in branching_steps["decidir_caminho_severidade"].get("branches", [])
            ],
            ["critical", "high"],
        )
        self.assertEqual(
            [
                step.get("name")
                for step in branching_steps["decidir_caminho_severidade"].get("default", [])
            ],
            ["note_resposta_padrao"],
        )

        automatic_playbooks = [
            playbook
            for playbook in Playbook.objects.filter(enabled=True)
            if (playbook.dsl or {}).get("mode") == "automatic"
        ]
        self.assertGreater(len(automatic_playbooks), 0)
        for playbook in automatic_playbooks:
            triggers = playbook.dsl.get("triggers", [])
            self.assertGreater(len(triggers), 0)
            for trigger in triggers:
                self.assertEqual(
                    trigger.get("filters", {}).get("exclude_labels"),
                    ["manual-treatment"],
                    msg=f"Playbook '{playbook.name}' sem guard de manual-treatment no trigger {trigger.get('event')}",
                )

    @override_settings(
        CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}},
        CELERY_TASK_ALWAYS_EAGER=True,
    )
    def test_seeded_branching_demo_executes_all_runtime_paths(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())

        actor = User.objects.get(username="analyst")
        playbook = Playbook.objects.get(name="Branching decision demo")
        scenarios = [
            {
                "severity": Incident.Severity.CRITICAL,
                "selected_branch": "critical",
                "matched": True,
                "used_default": False,
                "executed_steps": ["task_resposta_critica", "note_resposta_critica"],
                "task_title": "Acionar resposta critica e coordenacao executiva",
                "absent_task_title": "Priorizar resposta de severidade alta",
            },
            {
                "severity": Incident.Severity.HIGH,
                "selected_branch": "high",
                "matched": True,
                "used_default": False,
                "executed_steps": ["task_resposta_alta", "note_resposta_alta"],
                "task_title": "Priorizar resposta de severidade alta",
                "absent_task_title": "Acionar resposta critica e coordenacao executiva",
            },
            {
                "severity": Incident.Severity.LOW,
                "selected_branch": "default",
                "matched": False,
                "used_default": True,
                "executed_steps": ["note_resposta_padrao"],
                "task_title": None,
                "absent_task_title": "Acionar resposta critica e coordenacao executiva",
            },
        ]

        for scenario in scenarios:
            with self.subTest(severity=scenario["severity"]):
                incident = Incident.objects.create(
                    title=f"Branching demo {scenario['severity']}",
                    description="Runtime validation for the seeded control.branch demo.",
                    severity=scenario["severity"],
                    labels=["branching-demo"],
                    created_by=actor,
                )
                available_playbooks = {
                    item.name
                    for item in get_manual_playbooks_for_incident(incident)
                }
                self.assertIn("Branching decision demo", available_playbooks)

                execution = start_playbook_execution(
                    playbook,
                    incident,
                    actor=actor,
                    force_sync=True,
                    context={"event": "manual.incident"},
                )

                execution.refresh_from_db()
                self.assertEqual(execution.status, Execution.Status.SUCCEEDED)
                branch_result = execution.step_results.get(step_name="decidir_caminho_severidade")
                self.assertEqual(branch_result.result["selected_branch"], scenario["selected_branch"])
                self.assertEqual(branch_result.result["matched"], scenario["matched"])
                self.assertEqual(branch_result.result["used_default"], scenario["used_default"])
                self.assertEqual(branch_result.result["executed_steps"], scenario["executed_steps"])
                self.assertTrue(
                    incident.timeline.filter(
                        message=(
                            "Demo de branching concluida. Branch selecionado: "
                            f"{scenario['selected_branch']}."
                        )
                    ).exists()
                )
                if scenario["task_title"]:
                    self.assertTrue(incident.tasks.filter(title=scenario["task_title"]).exists())
                self.assertFalse(incident.tasks.filter(title=scenario["absent_task_title"]).exists())

    def test_seed_demo_structures_only_skips_incident_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, structures_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(IntegrationDefinition.objects.filter(action_name="virustotal_config.domain_lookup").exists())
        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="Credential compromise manual checklist", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="Malware phishing containment", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="Malware suspected manual checklist", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="Mailbox compromise manual checklist", category="Tratamento - Phishing").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="IOC malicious infrastructure response", category="Tratamento - IOC").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="IOC malicious infrastructure manual checklist", category="Tratamento - IOC").exists()
        )
        self.assertTrue(
            Playbook.objects.filter(name="Branching decision demo", category="Auxiliar - Geral").exists()
        )
        self.assertEqual(Incident.objects.count(), 0)

    def test_seed_demo_incidents_only_skips_structure_seed(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, incidents_only=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo credential compromise - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo credential compromise - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo malware - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo malware - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo mailbox compromise - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo mailbox compromise - MANUAL").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - MANUAL").exists())
        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())

    def test_seed_demo_phishing_comparison_only_mode(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, phishing_comparison=True, stdout=StringIO())

        self.assertTrue(User.objects.filter(username="admin").exists())
        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())
        self.assertFalse(Incident.objects.filter(title="Email suspeito de phishing").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo credential compromise - AUTO").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo credential compromise - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo malware - AUTO").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo malware - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo mailbox compromise - AUTO").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo mailbox compromise - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - AUTO").exists())
        self.assertFalse(Incident.objects.filter(title="Comparativo IOC malicious infrastructure - MANUAL").exists())

        auto_incident = Incident.objects.get(title="Comparativo phishing - AUTO")
        auto_domain = auto_incident.artifacts.filter(type="DOMAIN", value="compare-auto.example").first()
        self.assertIsNotNone(auto_domain)
        self.assertEqual((auto_domain.attributes or {}).get("siem_source"), "SOC-SIEM")
        self.assertEqual((auto_domain.attributes or {}).get("alert_id"), "SIM-PHISH-AUTO-001")

    def test_seed_demo_rejects_conflicting_modes(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", force=True, structures_only=True, incidents_only=True, stdout=StringIO())
            with self.assertRaises(CommandError):
                call_command("seed_demo", force=True, structures_only=True, phishing_comparison=True, stdout=StringIO())

    def test_seed_wrapper_commands(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_structures", force=True, stdout=StringIO())

        self.assertTrue(
            Playbook.objects.filter(name="Phishing triage", category="Tratamento - Phishing").exists()
        )
        self.assertFalse(Incident.objects.exists())

        Incident.objects.all().delete()
        Playbook.objects.all().delete()
        IntegrationDefinition.objects.all().delete()

        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_incidents", force=True, stdout=StringIO())

        self.assertTrue(Incident.objects.filter(title="Email suspeito de phishing").exists())

        Incident.objects.all().delete()
        Playbook.objects.all().delete()
        IntegrationDefinition.objects.all().delete()

        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_phishing_comparison", force=True, stdout=StringIO())

        self.assertFalse(IntegrationDefinition.objects.exists())
        self.assertFalse(Playbook.objects.exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - AUTO").exists())
        self.assertTrue(Incident.objects.filter(title="Comparativo phishing - MANUAL").exists())
        self.assertFalse(Incident.objects.filter(title="Email suspeito de phishing").exists())
