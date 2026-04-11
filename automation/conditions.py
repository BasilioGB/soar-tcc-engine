from __future__ import annotations

from typing import Any

from .input_resolution import validate_step_input_placeholders, resolve_step_input

SIMPLE_OPERATORS = {"equals", "not_equals", "in", "contains"}


def should_run_step(condition: Any, context: dict[str, Any]) -> bool:
    if condition is None:
        return True
    return _evaluate_condition(condition, context)


def validate_condition_spec(condition: Any) -> None:
    if condition is None or isinstance(condition, bool):
        return

    if isinstance(condition, (int, float)):
        return

    if isinstance(condition, str):
        validate_step_input_placeholders(condition)
        return

    if not isinstance(condition, dict):
        raise ValueError("Condicao 'when' deve ser bool, numero, string ou objeto")

    if "all" in condition:
        _ensure_exact_keys(condition, {"all"}, "all")
        clauses = condition["all"]
        if not isinstance(clauses, list):
            raise ValueError("Condicao 'all' deve ser uma lista")
        for clause in clauses:
            validate_condition_spec(clause)
        return

    if "any" in condition:
        _ensure_exact_keys(condition, {"any"}, "any")
        clauses = condition["any"]
        if not isinstance(clauses, list):
            raise ValueError("Condicao 'any' deve ser uma lista")
        for clause in clauses:
            validate_condition_spec(clause)
        return

    if "not" in condition:
        _ensure_exact_keys(condition, {"not"}, "not")
        validate_condition_spec(condition["not"])
        return

    if "exists" in condition:
        _ensure_exact_keys(condition, {"left", "exists"}, "exists")
        if not isinstance(condition["exists"], bool):
            raise ValueError("Condicao 'exists' exige valor booleano")
        validate_step_input_placeholders(condition["left"])
        return

    if "left" not in condition:
        raise ValueError("Condicao invalida: campo 'left' ausente")

    operators = SIMPLE_OPERATORS.intersection(condition.keys())
    if len(operators) != 1:
        raise ValueError(
            "Condicao invalida: informe exatamente um operador entre "
            "'equals', 'not_equals', 'in' ou 'contains'"
        )

    operator = next(iter(operators))
    expected_keys = {"left", operator}
    _ensure_exact_keys(condition, expected_keys, operator)
    validate_step_input_placeholders(condition["left"])
    validate_step_input_placeholders(condition[operator])


def _evaluate_condition(condition: Any, context: dict[str, Any]) -> bool:
    if isinstance(condition, bool):
        return condition

    if isinstance(condition, str):
        return bool(resolve_step_input(condition, context))

    if not isinstance(condition, dict):
        return bool(resolve_step_input(condition, context))

    if "all" in condition:
        clauses = condition["all"]
        if not isinstance(clauses, list):
            raise ValueError("Condicao 'all' deve ser uma lista")
        return all(_evaluate_condition(clause, context) for clause in clauses)

    if "any" in condition:
        clauses = condition["any"]
        if not isinstance(clauses, list):
            raise ValueError("Condicao 'any' deve ser uma lista")
        return any(_evaluate_condition(clause, context) for clause in clauses)

    if "not" in condition:
        return not _evaluate_condition(condition["not"], context)

    if "exists" in condition:
        exists_expected = bool(condition["exists"])
        left = condition.get("left")
        if left is None:
            raise ValueError("Condicao 'exists' exige o campo 'left'")
        try:
            resolve_step_input(left, context)
            exists_actual = True
        except ValueError:
            exists_actual = False
        return exists_actual == exists_expected

    if "left" not in condition:
        raise ValueError("Condicao invalida: campo 'left' ausente")

    left = resolve_step_input(condition["left"], context)

    if "equals" in condition:
        return left == resolve_step_input(condition["equals"], context)

    if "not_equals" in condition:
        return left != resolve_step_input(condition["not_equals"], context)

    if "in" in condition:
        right = resolve_step_input(condition["in"], context)
        if not isinstance(right, (list, tuple, set)):
            raise ValueError("Condicao 'in' exige lista/tupla/conjunto no lado direito")
        return left in right

    if "contains" in condition:
        right = resolve_step_input(condition["contains"], context)
        if isinstance(left, dict):
            return right in left
        if isinstance(left, (list, tuple, set, str)):
            return right in left
        raise ValueError("Condicao 'contains' exige string, lista, conjunto, tupla ou dict no lado esquerdo")

    raise ValueError("Condicao invalida: operador nao suportado")


def _ensure_exact_keys(condition: dict[str, Any], expected: set[str], operator_name: str) -> None:
    extra = set(condition.keys()) - expected
    missing = expected - set(condition.keys())
    if missing or extra:
        raise ValueError(
            f"Condicao '{operator_name}' invalida: esperado {sorted(expected)}, "
            f"recebido {sorted(condition.keys())}"
        )
