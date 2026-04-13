from __future__ import annotations

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Seed only phishing comparison incidents (AUTO x MANUAL) with SIEM-like artifacts."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Permite executar o seed mesmo sem ALLOW_DEMO_SEED=1.",
        )

    def handle(self, *args, **options):
        call_command(
            "seed_demo",
            force=bool(options.get("force")),
            phishing_comparison=True,
            stdout=self.stdout,
            stderr=self.stderr,
        )

