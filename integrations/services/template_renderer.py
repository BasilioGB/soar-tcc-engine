from __future__ import annotations

from typing import Any

from automation.input_resolution import (
    collect_placeholder_expressions,
    resolve_step_input,
    validate_step_input_placeholders,
)


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


def extract_expected_params(value: Any) -> list[str]:
    params: list[str] = []
    seen: set[str] = set()
    for expression in collect_placeholder_expressions(value):
        if not expression.path.startswith("params."):
            continue
        _, _, remainder = expression.path.partition(".")
        param_name = remainder.split(".", 1)[0].strip()
        if not param_name or param_name in seen:
            continue
        seen.add(param_name)
        params.append(param_name)
    return params


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


def render_output_template(
    output_template: Any,
    runtime_context: dict[str, Any] | None,
    *,
    params: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
) -> Any:
    context = build_render_context(
        runtime_context,
        params=params,
        response=response,
    )
    return render_template_structure(output_template, context)
