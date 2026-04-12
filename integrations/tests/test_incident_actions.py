from __future__ import annotations

from email.message import EmailMessage
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase

from incidents.models import Incident
from incidents.services import add_artifact_link
from integrations.registry import get_action_executor


class ArtifactActionsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="artifact_lead", password="pass")
        self.incident = Incident.objects.create(
            title="IOC enrichment",
            description="Validar enrichment em artefato",
            created_by=self.user,
        )
        self.artifact = add_artifact_link(
            incident=self.incident,
            value="example.com",
            type_code="DOMAIN",
            actor=self.user,
        )
        email_message = EmailMessage()
        email_message["From"] = '"Banco Falso" <alerts@example.com>'
        email_message["Reply-To"] = "support@example.net"
        email_message["To"] = "victim@corp.local"
        email_message["Subject"] = "Atualizacao urgente de cadastro"
        email_message["Message-ID"] = "<message-123@example.com>"
        email_message["Received"] = "from 198.51.100.10 by mx.corp.local"
        email_message["Received-SPF"] = "pass (sender SPF authorized)"
        email_message["Authentication-Results"] = (
            "mx.corp.local; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass action=none header.from=example.com"
        )
        email_message.set_content(
            "Clique em https://login.example.com/reset e em https://203.0.113.9/painel."
        )
        email_message.add_alternative(
            '<html><body><a href="https://portal.example.net/auth">Abrir portal</a></body></html>',
            subtype="html",
        )
        email_message.add_attachment(
            b"invoice-content",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.zip",
        )
        self.raw_email = email_message.as_string()

    def test_update_attributes_uses_artifact_instance_when_no_artifact_id(self):
        executor = get_action_executor("artifact.update_attributes")

        result = executor(
            step=SimpleNamespace(
                input={"attributes": {"virustotal": {"reputation": "malicious"}}}
            ),
            context={
                "incident": self.incident,
                "artifact_instance": self.artifact,
                "artifact": {"id": self.artifact.id, "value": self.artifact.value, "type": self.artifact.type},
                "actor": self.user,
            },
        )

        self.artifact.refresh_from_db()
        self.assertTrue(result["changed"])
        self.assertEqual(
            self.artifact.attributes["virustotal"]["reputation"],
            "malicious",
        )

    def test_update_attributes_supports_explicit_artifact_id(self):
        other_artifact = add_artifact_link(
            incident=self.incident,
            value="8.8.8.8",
            type_code="IP",
            actor=self.user,
        )
        executor = get_action_executor("artifact.update_attributes")

        result = executor(
            step=SimpleNamespace(
                input={
                    "artifact_id": other_artifact.id,
                    "attributes": {"source": "http-connector"},
                    "merge": False,
                }
            ),
            context={"incident": self.incident, "actor": self.user},
        )

        other_artifact.refresh_from_db()
        self.assertEqual(result["artifact_id"], other_artifact.id)
        self.assertEqual(other_artifact.attributes, {"source": "http-connector"})

    def test_update_attributes_fails_without_artifact_context(self):
        executor = get_action_executor("artifact.update_attributes")

        with self.assertRaisesMessage(ValueError, "Nenhum artefato disponivel no contexto"):
            executor(
                step=SimpleNamespace(input={"attributes": {"virustotal": {"reputation": "malicious"}}}),
                context={"incident": self.incident, "actor": self.user},
            )

    def test_update_artifact_updates_value_and_type(self):
        executor = get_action_executor("artifact.update")

        result = executor(
            step=SimpleNamespace(input={"value": "example.org", "type": "OTHER"}),
            context={
                "incident": self.incident,
                "artifact_instance": self.artifact,
                "artifact": {"id": self.artifact.id, "value": self.artifact.value, "type": self.artifact.type},
                "actor": self.user,
            },
        )

        self.artifact.refresh_from_db()
        self.assertTrue(result["changed"])
        self.assertEqual(self.artifact.value, "example.org")
        self.assertEqual(self.artifact.type, "OTHER")

    def test_update_hash_persists_sha256(self):
        executor = get_action_executor("artifact.update_hash")
        sha256 = "a" * 64

        result = executor(
            step=SimpleNamespace(input={"sha256": sha256}),
            context={
                "incident": self.incident,
                "artifact_instance": self.artifact,
                "artifact": {"id": self.artifact.id, "value": self.artifact.value, "type": self.artifact.type},
                "actor": self.user,
            },
        )

        self.artifact.refresh_from_db()
        self.assertTrue(result["changed"])
        self.assertEqual(self.artifact.sha256, sha256)

    def test_create_email_from_raw_creates_email_artifact_with_basic_headers(self):
        executor = get_action_executor("artifact.create_email_from_raw")

        result = executor(
            step=SimpleNamespace(input={"raw_message": self.raw_email}),
            context={"incident": self.incident, "actor": self.user},
        )

        email_artifact = self.incident.artifacts.get(pk=result["artifact_id"])
        self.assertEqual(email_artifact.type, "EMAIL")
        self.assertEqual(
            email_artifact.attributes["email_headers"]["message_id"],
            "<message-123@example.com>",
        )
        self.assertEqual(email_artifact.value, "<message-123@example.com>")
        self.assertIn("email_raw", email_artifact.attributes)

    def test_parse_email_headers_persists_header_details_on_artifact(self):
        create_email = get_action_executor("artifact.create_email_from_raw")
        parse_headers = get_action_executor("artifact.parse_email_headers")
        created = create_email(
            step=SimpleNamespace(input={"raw_message": self.raw_email}),
            context={"incident": self.incident, "actor": self.user},
        )
        email_artifact = self.incident.artifacts.get(pk=created["artifact_id"])

        result = parse_headers(
            step=SimpleNamespace(input={}),
            context={
                "incident": self.incident,
                "artifact_instance": email_artifact,
                "artifact": {"id": email_artifact.id, "value": email_artifact.value, "type": email_artifact.type},
                "actor": self.user,
            },
        )

        email_artifact.refresh_from_db()
        headers = result["headers"]
        self.assertEqual(headers["from"], "Banco Falso <alerts@example.com>")
        self.assertEqual(headers["reply_to"], "support@example.net")
        self.assertEqual(headers["authentication"]["spf"]["result"], "pass")
        self.assertEqual(headers["authentication"]["dkim"]["result"], "pass")
        self.assertEqual(headers["authentication"]["dmarc"]["result"], "pass")
        self.assertEqual(email_artifact.attributes["email_headers"]["subject"], "Atualizacao urgente de cadastro")

    def test_extract_links_returns_body_and_html_urls(self):
        create_email = get_action_executor("artifact.create_email_from_raw")
        extract_links = get_action_executor("artifact.extract_links")
        created = create_email(
            step=SimpleNamespace(input={"raw_message": self.raw_email}),
            context={"incident": self.incident, "actor": self.user},
        )
        email_artifact = self.incident.artifacts.get(pk=created["artifact_id"])

        result = extract_links(
            step=SimpleNamespace(input={}),
            context={
                "incident": self.incident,
                "artifact_instance": email_artifact,
                "artifact": {"id": email_artifact.id, "value": email_artifact.value, "type": email_artifact.type},
                "actor": self.user,
            },
        )

        self.assertEqual(
            result["links"],
            [
                "https://login.example.com/reset",
                "https://203.0.113.9/painel",
                "https://portal.example.net/auth",
            ],
        )

    def test_extract_attachments_metadata_returns_filename_size_and_hash(self):
        create_email = get_action_executor("artifact.create_email_from_raw")
        extract_attachments = get_action_executor("artifact.extract_attachments_metadata")
        created = create_email(
            step=SimpleNamespace(input={"raw_message": self.raw_email}),
            context={"incident": self.incident, "actor": self.user},
        )
        email_artifact = self.incident.artifacts.get(pk=created["artifact_id"])

        result = extract_attachments(
            step=SimpleNamespace(input={}),
            context={
                "incident": self.incident,
                "artifact_instance": email_artifact,
                "artifact": {"id": email_artifact.id, "value": email_artifact.value, "type": email_artifact.type},
                "actor": self.user,
            },
        )

        attachment = result["attachments"][0]
        self.assertEqual(attachment["filename"], "invoice.zip")
        self.assertEqual(attachment["content_type"], "application/octet-stream")
        self.assertGreater(attachment["size"], 0)
        self.assertEqual(len(attachment["sha256"]), 64)

    def test_extract_iocs_from_email_combines_urls_domains_ips_and_attachment_names(self):
        create_email = get_action_executor("artifact.create_email_from_raw")
        extract_iocs = get_action_executor("artifact.extract_iocs_from_email")
        created = create_email(
            step=SimpleNamespace(input={"raw_message": self.raw_email}),
            context={"incident": self.incident, "actor": self.user},
        )
        email_artifact = self.incident.artifacts.get(pk=created["artifact_id"])

        result = extract_iocs(
            step=SimpleNamespace(input={}),
            context={
                "incident": self.incident,
                "artifact_instance": email_artifact,
                "artifact": {"id": email_artifact.id, "value": email_artifact.value, "type": email_artifact.type},
                "actor": self.user,
            },
        )

        iocs = result["iocs"]
        self.assertIn("https://login.example.com/reset", iocs["urls"])
        self.assertIn("login.example.com", iocs["domains"])
        self.assertIn("example.com", iocs["domains"])
        self.assertIn("203.0.113.9", iocs["ips"])
        self.assertIn("198.51.100.10", iocs["ips"])
        self.assertEqual(iocs["filenames"], ["invoice.zip"])
