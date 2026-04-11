from __future__ import annotations

from typing import Any

from automation.input_resolution import resolve_step_input, validate_step_input_placeholders


def build_render_context(
    runtime_context: dict[str, Any] | None,
    *,
    params: dict[str, Any] | None = None,
    output: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = dict(runtime_context or {})
    context["params"] = params or {}
    context["output"] = output or {}
    context["response"] = response or {}
    return context


def validate_template_structure(value: Any) -> None:
    validate_step_input_placeholders(value)


def render_template_structure(value: Any, context: dict[str, Any]) -> Any:
    return resolve_step_input(value, context)


def render_request_template(
    request_template: dict[str, Any],
    runtime_context: dict[str, Any] | None,
    *,
    params: dict[str, Any] | None = None,
    output: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(request_template, dict):
        raise ValueError("request_template deve ser um objeto JSON.")
    context = build_render_context(
        runtime_context,
        params=params,
        output=output,
        response=response,
    )
    return render_template_structure(request_template, context)


def render_post_response_actions(
    post_response_actions: list[dict[str, Any]],
    runtime_context: dict[str, Any] | None,
    *,
    params: dict[str, Any] | None = None,
    output: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(post_response_actions, list):
        raise ValueError("post_response_actions deve ser uma lista.")
    context = build_render_context(
        runtime_context,
        params=params,
        output=output,
        response=response,
    )
    rendered = render_template_structure(post_response_actions, context)
    if not isinstance(rendered, list):
        raise ValueError("post_response_actions renderizado deve permanecer uma lista.")
    return rendered
