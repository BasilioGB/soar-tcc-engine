from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from typing import Any


PATH_PATTERN = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.(?:[A-Za-z_][A-Za-z0-9_]*|\d+))*$"
)
MISSING = object()


@dataclass(frozen=True)
class PlaceholderFilter:
    name: str
    arg: Any = None


@dataclass(frozen=True)
class PlaceholderExpression:
    path: str
    filters: tuple[PlaceholderFilter, ...]


def resolve_step_input(value: Any, context: dict[str, Any]) -> Any:
    return _resolve_value(value, context)


def validate_step_input_placeholders(value: Any) -> None:
    _validate_value(value)


def collect_placeholder_expressions(value: Any) -> tuple[PlaceholderExpression, ...]:
    expressions: list[PlaceholderExpression] = []
    _collect_value_placeholders(value, expressions)
    return tuple(expressions)


def _validate_value(value: Any) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _validate_value(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_value(item)
        return
    if isinstance(value, str):
        _parse_template(value)


def _collect_value_placeholders(value: Any, expressions: list[PlaceholderExpression]) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _collect_value_placeholders(item, expressions)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_value_placeholders(item, expressions)
        return
    if isinstance(value, str):
        expressions.extend(expression for _, _, expression in _parse_template(value))


def _resolve_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, dict):
        return {key: _resolve_value(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_value(item, context) for item in value]
    if isinstance(value, tuple):
        return tuple(_resolve_value(item, context) for item in value)
    if isinstance(value, str):
        return _resolve_string(value, context)
    return value


def _resolve_string(template: str, context: dict[str, Any]) -> Any:
    placeholders = _parse_template(template)
    if not placeholders:
        return template

    if len(placeholders) == 1 and placeholders[0][0] == 0 and placeholders[0][1] == len(template):
        return _evaluate_expression(placeholders[0][2], context)

    rendered: list[str] = []
    cursor = 0
    for start, end, expression in placeholders:
        rendered.append(template[cursor:start])
        rendered.append(_stringify_for_interpolation(_evaluate_expression(expression, context)))
        cursor = end
    rendered.append(template[cursor:])
    return "".join(rendered)


def _parse_template(template: str) -> list[tuple[int, int, PlaceholderExpression]]:
    placeholders: list[tuple[int, int, PlaceholderExpression]] = []
    index = 0

    while index < len(template):
        start = template.find("{{", index)
        stray_end = template.find("}}", index)

        if stray_end != -1 and (start == -1 or stray_end < start):
            raise ValueError(f"Placeholder malformado: fechamento sem abertura em '{template}'")

        if start == -1:
            break

        end = template.find("}}", start + 2)
        if end == -1:
            raise ValueError(f"Placeholder malformado: fechamento ausente em '{template}'")

        body = template[start + 2 : end].strip()
        if not body:
            raise ValueError(f"Placeholder vazio em '{template}'")

        placeholders.append((start, end + 2, _parse_expression(body)))
        index = end + 2

    if template.find("}}", index) != -1:
        raise ValueError(f"Placeholder malformado: fechamento sem abertura em '{template}'")

    return placeholders


def _parse_expression(body: str) -> PlaceholderExpression:
    parts = [part.strip() for part in _split_unquoted(body, "|")]
    if not parts or not parts[0]:
        raise ValueError(f"Placeholder invalido: '{body}'")

    path = parts[0]
    if not PATH_PATTERN.match(path):
        raise ValueError(f"Caminho de placeholder invalido: '{path}'")

    filters: list[PlaceholderFilter] = []
    for raw_filter in parts[1:]:
        filters.append(_parse_filter(raw_filter, body))

    return PlaceholderExpression(path=path, filters=tuple(filters))


def _parse_filter(raw_filter: str, body: str) -> PlaceholderFilter:
    if not raw_filter:
        raise ValueError(f"Filtro vazio em placeholder '{body}'")

    name, arg = _split_filter(raw_filter)
    if name not in FILTER_SPECS:
        raise ValueError(f"Filtro desconhecido '{name}' em placeholder '{body}'")

    requires_arg = FILTER_SPECS[name]["requires_arg"]
    if requires_arg and arg is None:
        raise ValueError(f"Filtro '{name}' exige argumento em placeholder '{body}'")
    if not requires_arg and arg is not None:
        raise ValueError(f"Filtro '{name}' nao aceita argumento em placeholder '{body}'")

    parsed_arg = _parse_literal(arg) if arg is not None else None
    return PlaceholderFilter(name=name, arg=parsed_arg)


def _split_filter(raw_filter: str) -> tuple[str, str | None]:
    quote: str | None = None
    for index, char in enumerate(raw_filter):
        if char in {'"', "'"}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            continue
        if char == ":" and quote is None:
            name = raw_filter[:index].strip()
            arg = raw_filter[index + 1 :].strip()
            return name, arg or None
    return raw_filter.strip(), None


def _split_unquoted(value: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False

    for char in value:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\" and quote is not None:
            current.append(char)
            escape = True
            continue
        if char in {'"', "'"}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            current.append(char)
            continue
        if char == delimiter and quote is None:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)

    if quote is not None:
        raise ValueError(f"String literal nao fechada em '{value}'")

    parts.append("".join(current))
    return parts


def _parse_literal(raw_arg: str) -> Any:
    if raw_arg is None:
        return None
    candidate = raw_arg.strip()
    if not candidate:
        return ""

    if candidate[0] in {"'", '"'}:
        try:
            return ast.literal_eval(candidate)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"Literal invalido em filtro: {raw_arg}") from exc

    lowered = candidate.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None

    try:
        return int(candidate)
    except ValueError:
        pass

    try:
        return float(candidate)
    except ValueError:
        return candidate


def _evaluate_expression(expression: PlaceholderExpression, context: dict[str, Any]) -> Any:
    value, missing_error = _resolve_path_with_error(expression.path, context)

    for placeholder_filter in expression.filters:
        if value is MISSING and placeholder_filter.name != "default":
            raise ValueError(missing_error)
        value = FILTER_SPECS[placeholder_filter.name]["handler"](
            value,
            placeholder_filter.arg,
            expression.path,
            missing_error,
        )

    if value is MISSING:
        raise ValueError(missing_error)
    return value


def _resolve_path_with_error(path: str, context: dict[str, Any]) -> tuple[Any, str]:
    current: Any = context
    traversed: list[str] = []

    for segment in path.split("."):
        traversed.append(segment)
        if current is None:
            return MISSING, _missing_message(path, segment, traversed[:-1])

        if isinstance(current, dict):
            if segment in current:
                current = current[segment]
                continue
            return MISSING, _missing_message(path, segment, traversed[:-1])

        if isinstance(current, (list, tuple)):
            if not segment.isdigit():
                return MISSING, (
                    f"Placeholder '{path}' exige indice numerico para acessar listas em '{segment}'"
                )
            index = int(segment)
            if 0 <= index < len(current):
                current = current[index]
                continue
            return MISSING, _missing_message(path, segment, traversed[:-1])

        if hasattr(current, segment):
            current = getattr(current, segment)
            continue

        return MISSING, _missing_message(path, segment, traversed[:-1])

    return current, ""


def _missing_message(path: str, segment: str, traversed: list[str]) -> str:
    if traversed:
        parent = ".".join(traversed)
        return (
            f"Placeholder '{path}' nao encontrado: '{segment}' ausente sob '{parent}'"
        )
    return f"Placeholder '{path}' nao encontrado: chave raiz '{segment}' ausente"


def _filter_default(value: Any, arg: Any, path: str, missing_error: str) -> Any:
    if value is MISSING or value is None or value == "":
        return arg
    return value


def _filter_lower(value: Any, arg: Any, path: str, missing_error: str) -> Any:
    return str(value).lower()


def _filter_upper(value: Any, arg: Any, path: str, missing_error: str) -> Any:
    return str(value).upper()


def _filter_strip(value: Any, arg: Any, path: str, missing_error: str) -> Any:
    return str(value).strip()


def _filter_length(value: Any, arg: Any, path: str, missing_error: str) -> int:
    try:
        return len(value)
    except TypeError as exc:
        raise ValueError(f"Filtro 'length' nao pode ser aplicado ao placeholder '{path}'") from exc


def _filter_json(value: Any, arg: Any, path: str, missing_error: str) -> str:
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError as exc:
        raise ValueError(f"Filtro 'json' nao pode serializar o placeholder '{path}'") from exc


def _filter_join(value: Any, arg: Any, path: str, missing_error: str) -> str:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"Filtro 'join' exige lista/tupla no placeholder '{path}'")
    separator = "" if arg is None else str(arg)
    return separator.join("" if item is None else str(item) for item in value)


FILTER_SPECS: dict[str, dict[str, Any]] = {
    "default": {"handler": _filter_default, "requires_arg": True},
    "lower": {"handler": _filter_lower, "requires_arg": False},
    "upper": {"handler": _filter_upper, "requires_arg": False},
    "strip": {"handler": _filter_strip, "requires_arg": False},
    "length": {"handler": _filter_length, "requires_arg": False},
    "json": {"handler": _filter_json, "requires_arg": False},
    "join": {"handler": _filter_join, "requires_arg": True},
}


def _stringify_for_interpolation(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float, dict, list, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except TypeError:
            return str(value)
    return str(value)
