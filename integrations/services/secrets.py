from __future__ import annotations

import os

from integrations.models import IntegrationSecretRef


def resolve_secret_value(secret_ref: IntegrationSecretRef) -> str:
    if not secret_ref.enabled:
        raise ValueError(f"Secret ref '{secret_ref.name}' esta desabilitado")

    if secret_ref.provider == IntegrationSecretRef.Provider.ENV:
        value = os.getenv(secret_ref.reference, "")
        if not value:
            raise ValueError(
                f"Variavel de ambiente '{secret_ref.reference}' nao encontrada para o secret_ref '{secret_ref.name}'"
            )
        return value

    raise ValueError(f"Provider de secret nao suportado: {secret_ref.provider}")
