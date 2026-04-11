from __future__ import annotations

from typing import Any, Callable, Dict

from integrations.models import IntegrationDefinition

ActionCallable = Callable[..., Any]

_REGISTRY: Dict[str, ActionCallable] = {}


def register(action_name: str):
    def decorator(func: ActionCallable) -> ActionCallable:
        _REGISTRY[action_name] = func
        return func

    return decorator


def get_action_executor(action_name: str) -> ActionCallable | None:
    static_executor = _REGISTRY.get(action_name)
    if static_executor is not None:
        return static_executor

    integration = (
        IntegrationDefinition.objects.select_related("secret_ref")
        .filter(action_name=action_name, enabled=True)
        .first()
    )
    if integration is None:
        return None

    from integrations.services.configured_executor import execute_configured_integration

    def configured_executor(*, step, context: dict[str, Any]):
        return execute_configured_integration(
            integration=integration,
            params=step.input,
            runtime_context=context,
        )

    return configured_executor


def list_actions() -> list[str]:
    return sorted(_REGISTRY.keys())


from integrations.actions import http_webhook, incident_actions, virustotal  # noqa: E402,F401
