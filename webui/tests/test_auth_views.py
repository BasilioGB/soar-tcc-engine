from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class LogoutViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="logout_user",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.admin = User.objects.create_superuser(
            username="logout_admin",
            email="logout_admin@example.com",
            password="pass",
        )

    def test_webui_logout_renders_custom_screen_and_redirect_hint(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse("webui:logout"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/logged_out.html")
        self.assertContains(response, "Sessao encerrada")
        self.assertContains(response, reverse("webui:login"))
        self.assertNotContains(response, "Acessar novamente")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_admin_logout_redirects_to_login(self):
        self.client.force_login(self.admin)

        response = self.client.post(reverse("admin:logout"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers.get("Location"), reverse("webui:login"))
