from __future__ import annotations

import os
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from accounts.models import User


class SeedDemoCommandHardeningTests(TestCase):
    def test_seed_demo_requires_opt_in(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            with self.assertRaises(CommandError):
                call_command("seed_demo", stdout=StringIO())

    def test_seed_demo_accepts_force_flag(self):
        with patch.dict(os.environ, {"ALLOW_DEMO_SEED": ""}, clear=False):
            call_command("seed_demo", force=True, stdout=StringIO())
        self.assertTrue(User.objects.filter(username="admin").exists())
