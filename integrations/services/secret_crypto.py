from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings


def encrypt_secret(value: str) -> str:
    return _get_fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    return _get_fernet().decrypt(value.encode("utf-8")).decode("utf-8")


def _get_fernet() -> Fernet:
    key_source = getattr(settings, "INTEGRATIONS_SECRET_ENCRYPTION_KEY", "") or settings.SECRET_KEY
    digest = hashlib.sha256(key_source.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))
