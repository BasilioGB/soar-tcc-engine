from __future__ import annotations

from typing import Any, Callable, Dict

ActionCallable = Callable[..., Any]

_REGISTRY: Dict[str, ActionCallable] = {}


def register(action_name: str):
    def decorator(func: ActionCallable) -> ActionCallable:
        _REGISTRY[action_name] = func
        return func

    return decorator


def get_action_executor(action_name: str) -> ActionCallable | None:
    return _REGISTRY.get(action_name)


def list_actions() -> list[str]:
    return sorted(_REGISTRY.keys())


from integrations.actions import http_webhook, incident_actions, virustotal  # noqa: E402,F401
