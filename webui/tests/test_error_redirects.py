from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


class WebUIErrorRedirectTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user(
            username="error_analyst",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )

    def test_not_found_redirects_to_dashboard_with_warning(self):
        self.client.force_login(self.analyst)

        response = self.client.get("/rota-que-nao-existe/", follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request["PATH_INFO"], reverse("webui:dashboard"))
        self.assertContains(response, "A pagina solicitada nao existe.")

    def test_permission_denied_redirects_to_dashboard_with_warning(self):
        self.client.force_login(self.analyst)

        response = self.client.get(reverse("webui:http_connector_list"), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request["PATH_INFO"], reverse("webui:dashboard"))
        self.assertContains(response, "Voce nao tem permissao para acessar esta pagina.")

    def test_api_not_found_keeps_404(self):
        response = self.client.get("/api/rota-que-nao-existe/")

        self.assertEqual(response.status_code, 404)
