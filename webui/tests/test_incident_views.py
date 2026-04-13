from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from incidents.models import Incident


class IncidentListOwnershipFilterTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            username="owner_user",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.other = User.objects.create_user(
            username="other_user",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.mine_incident = Incident.objects.create(
            title="Incidente meu",
            description="Atribuido para mim",
            created_by=self.other,
            assignee=self.user,
        )
        self.escalated_incident = Incident.objects.create(
            title="Incidente escalado",
            description="Escalado para mim",
            created_by=self.other,
            assignee=self.other,
        )
        self.escalated_incident.secondary_assignees.add(self.user)
        self.other_incident = Incident.objects.create(
            title="Incidente de terceiro",
            description="Nao e meu nem escalado para mim",
            created_by=self.other,
            assignee=self.other,
        )

    def test_filter_mine(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse("webui:incident_list"), {"ownership": "mine"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.mine_incident.title)
        self.assertNotContains(response, self.escalated_incident.title)
        self.assertNotContains(response, self.other_incident.title)

    def test_filter_escalated_to_me(self):
        self.client.force_login(self.user)

        response = self.client.get(reverse("webui:incident_list"), {"ownership": "escalated"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.escalated_incident.title)
        self.assertNotContains(response, self.mine_incident.title)
        self.assertNotContains(response, self.other_incident.title)


class IncidentEscalationSecondaryAssigneeTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.lead = User.objects.create_user(
            username="lead_escalation",
            password="pass",
            role=User.Roles.SOC_LEAD,
        )
        self.analyst = User.objects.create_user(
            username="analyst_escalation",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        self.incident = Incident.objects.create(
            title="Incidente para escalonamento",
            description="Teste de secundarios",
            created_by=self.lead,
            assignee=self.lead,
        )

    def test_escalation_update_persists_secondary_assignees(self):
        self.client.force_login(self.lead)

        response = self.client.post(
            reverse("webui:incident_escalation_update", kwargs={"pk": self.incident.pk}),
            {
                "level": "tier2",
                "secondary_assignees": [str(self.analyst.id)],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.incident.refresh_from_db()
        self.assertEqual(self.incident.escalation_level, "tier2")
        self.assertEqual(
            set(self.incident.secondary_assignees.values_list("id", flat=True)),
            {self.analyst.id},
        )
        self.assertEqual(self.incident.escalation_targets, [self.analyst.get_username()])

    def test_escalation_user_search_filters_results(self):
        self.client.force_login(self.lead)
        User = get_user_model()
        matched = User.objects.create_user(
            username="analyst_search_match",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )
        User.objects.create_user(
            username="non_matching_user",
            password="pass",
            role=User.Roles.SOC_ANALYST,
        )

        response = self.client.get(
            reverse("webui:incident_escalation_user_search", kwargs={"pk": self.incident.pk}),
            {"q": "search_match"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, matched.get_username())
        self.assertNotContains(response, "non_matching_user")

    def test_escalation_user_search_marks_selected_users(self):
        self.client.force_login(self.lead)

        response = self.client.get(
            reverse("webui:incident_escalation_user_search", kwargs={"pk": self.incident.pk}),
            {
                "q": self.analyst.get_username(),
                "secondary_assignees": [str(self.analyst.id)],
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Selecionado")
