from __future__ import annotations

from integrations.models import IntegrationSecretRef


def resolve_secret_credentials(secret_ref: IntegrationSecretRef) -> dict[str, str]:
    if not secret_ref.enabled:
        raise ValueError(f"Secret ref '{secret_ref.name}' esta desabilitado")
    if not secret_ref.has_credential:
        raise ValueError(f"Secret ref '{secret_ref.name}' nao possui credencial armazenada")
    return secret_ref.get_credential()
