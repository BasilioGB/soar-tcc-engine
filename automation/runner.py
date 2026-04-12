from __future__ import annotations

from dataclasses import dataclass
import json
from time import perf_counter
from typing import Any, Callable

from django.utils import timezone

from audit.utils import log_action
from incidents.models import Artifact, TimelineEntry
from incidents.services import update_incident_lifecycle
from integrations.registry import get_action_executor
from playbooks.dsl import ParsedStep, PlaybookType, parse_playbook
from playbooks.models import Execution, ExecutionLog, ExecutionStepResult

from .conditions import should_run_step
from .exceptions import StepExecutionError
from .input_resolution import resolve_step_input


@dataclass
class StepRuntimeResult:
    step_name: str
    step_order: int
    status: str
    started_at: Any
    finished_at: Any
    resolved_input: dict[str, Any] | None = None
    result: Any = None
    error: StepExecutionError | None = None
    skipped_reason: str | None = None
    duration_ms: int = 0


def _create_log(execution: Execution, level: str, message: str, step_name: str = "") -> ExecutionLog:
    return ExecutionLog.objects.create(execution=execution, level=level, message=message, step_name=step_name)


def run_execution_sync(execution_id: int) -> Execution:
    execution = Execution.objects.select_related("playbook", "incident").get(pk=execution_id)
    return _run_execution(execution)


def enqueue_execution(execution_id: int) -> None:
    from .tasks import run_playbook_execution

    run_playbook_execution.delay(execution_id)


def _build_runtime_context(execution: Execution, playbook_type: PlaybookType) -> dict[str, Any]:
    context: dict[str, Any] = {
        "incident": execution.incident,
        "execution": execution,
        "results": {},
        "actor": execution.created_by,
        "playbook_type": playbook_type.value,
        "trigger_context": execution.context or {},
    }
    if playbook_type == PlaybookType.ARTIFACT:
        _attach_artifact_context(context, execution.incident)
    return context


def _attach_artifact_context(context: dict[str, Any], incident) -> None:
    trigger_context = context.get("trigger_context")
    if not isinstance(trigger_context, dict):
        return

    artifact_payload = trigger_context.get("artifact") or {}
    artifact_obj = None
    artifact_id = artifact_payload.get("id") if isinstance(artifact_payload, dict) else None

    if artifact_id:
        try:
            artifact_obj = incident.artifacts.get(pk=artifact_id)
        except Artifact.DoesNotExist:
            artifact_obj = Artifact.objects.filter(pk=artifact_id).first()

    if artifact_obj:
        context["artifact_instance"] = artifact_obj
        artifact_payload = artifact_payload or {}
        artifact_payload.setdefault("id", artifact_obj.id)
        artifact_payload.setdefault("type", artifact_obj.type)
        artifact_payload.setdefault("value", artifact_obj.value)
        artifact_payload["attributes"] = artifact_obj.attributes or {}

    context["artifact"] = artifact_payload


def evaluate_when(step: ParsedStep, context: dict[str, Any]) -> bool:
    return should_run_step(step.when, context)


def resolve_step_inputs(step: ParsedStep, context: dict[str, Any]) -> ParsedStep:
    return ParsedStep(
        name=step.name,
        action=step.action,
        input=resolve_step_input(step.input, context),
        when=step.when,
    )


def execute_action(
    step: ParsedStep,
    executor: Callable[..., Any],
    context: dict[str, Any],
) -> Any:
    return executor(step=step, context=context)


def _to_json_compatible(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _to_json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_json_compatible(item) for item in value]
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _result_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value.keys())
    return []


def _result_for_runtime_context(value: Any) -> Any:
    if (
        isinstance(value, dict)
        and "output" in value
        and "action_name" in value
        and "connector_revision" in value
    ):
        return value.get("output")
    return value


def _step_log_message(step_result: StepRuntimeResult) -> str:
    if step_result.status == "SKIPPED":
        return (
            f"status=SKIPPED step={step_result.step_name} "
            f"skipped_reason={step_result.skipped_reason}"
        )
    if step_result.status == "SUCCEEDED":
        return (
            f"status=SUCCEEDED step={step_result.step_name} "
            f"duration_ms={step_result.duration_ms} result_keys={_result_keys(step_result.result)}"
        )
    error_class = step_result.error.__class__.__name__ if step_result.error is not None else ""
    error_message = str(step_result.error) if step_result.error is not None else ""
    return (
        f"status=FAILED step={step_result.step_name} duration_ms={step_result.duration_ms} "
        f"error_class={error_class} error={error_message}"
    )


def persist_step_result(
    execution: Execution,
    context: dict[str, Any],
    step_result: StepRuntimeResult,
) -> None:
    if step_result.status == "SKIPPED":
        context["results"][step_result.step_name] = {
            "skipped": True,
            "reason": step_result.skipped_reason,
        }
    elif step_result.status == "SUCCEEDED":
        context["results"][step_result.step_name] = _result_for_runtime_context(step_result.result)

    ExecutionStepResult.objects.create(
        execution=execution,
        step_name=step_result.step_name,
        step_order=step_result.step_order,
        status=step_result.status,
        started_at=step_result.started_at,
        finished_at=step_result.finished_at,
        duration_ms=step_result.duration_ms,
        resolved_input=_to_json_compatible(step_result.resolved_input or {}),
        result=_to_json_compatible(step_result.result),
        error_class=step_result.error.__class__.__name__ if step_result.error is not None else "",
        error_message=str(step_result.error) if step_result.error is not None else "",
        skipped_reason=step_result.skipped_reason or "",
    )

    _create_log(
        execution,
        ExecutionLog.Level.ERROR if step_result.status == "FAILED" else ExecutionLog.Level.INFO,
        _step_log_message(step_result),
        step_result.step_name,
    )


def run_step(
    *,
    execution: Execution,
    step: ParsedStep,
    step_order: int,
    executor: Callable[..., Any],
    context: dict[str, Any],
) -> StepRuntimeResult:
    started_at = timezone.now()
    started = perf_counter()

    if not evaluate_when(step, context):
        return StepRuntimeResult(
            step_name=step.name,
            step_order=step_order,
            status="SKIPPED",
            started_at=started_at,
            finished_at=started_at,
            skipped_reason="when",
        )

    _create_log(execution, ExecutionLog.Level.INFO, f"Executando passo '{step.name}'", step.name)

    try:
        resolved_step = resolve_step_inputs(step, context)
        result = execute_action(resolved_step, executor, context)
        finished_at = timezone.now()
        return StepRuntimeResult(
            step_name=step.name,
            step_order=step_order,
            status="SUCCEEDED",
            started_at=started_at,
            finished_at=finished_at,
            resolved_input=resolved_step.input,
            result=result,
            duration_ms=int((perf_counter() - started) * 1000),
        )
    except StepExecutionError as exc:
        finished_at = timezone.now()
        return StepRuntimeResult(
            step_name=step.name,
            step_order=step_order,
            status="FAILED",
            started_at=started_at,
            finished_at=finished_at,
            error=exc,
            duration_ms=int((perf_counter() - started) * 1000),
        )
    except Exception as exc:  # noqa: BLE001
        finished_at = timezone.now()
        return StepRuntimeResult(
            step_name=step.name,
            step_order=step_order,
            status="FAILED",
            started_at=started_at,
            finished_at=finished_at,
            error=StepExecutionError(step.name, str(exc)),
            duration_ms=int((perf_counter() - started) * 1000),
        )


def _run_execution(execution: Execution) -> Execution:
    playbook = execution.playbook
    incident = execution.incident
    parsed = parse_playbook(playbook.dsl)

    execution.status = Execution.Status.RUNNING
    execution.started_at = timezone.now()
    execution.save(update_fields=["status", "started_at"])

    if not incident.responded_at:
        update_incident_lifecycle(
            incident=incident,
            actor=execution.created_by,
            responded_at=timezone.now(),
        )

    TimelineEntry.objects.create(
        incident=incident,
        entry_type=TimelineEntry.EntryType.PLAYBOOK_EXECUTION,
        message=f"Execucao de playbook '{playbook.name}' iniciada",
        created_by=execution.created_by,
    )

    context = _build_runtime_context(execution, parsed.type)
    failures: list[str] = []

    for step_order, step in enumerate(parsed.steps, start=1):
        executor: Callable[..., Any] | None = get_action_executor(step.action)
        if executor is None:
            error = StepExecutionError(step.name, f"Acao '{step.action}' nao encontrada")
            failures.append(step.name)
            persist_step_result(
                execution,
                context,
                StepRuntimeResult(
                    step_name=step.name,
                    step_order=step_order,
                    status="FAILED",
                    started_at=timezone.now(),
                    finished_at=timezone.now(),
                    error=error,
                ),
            )
            if parsed.on_error == "stop":
                break
            continue

        step_result = run_step(
            execution=execution,
            step=step,
            step_order=step_order,
            executor=executor,
            context=context,
        )
        persist_step_result(execution, context, step_result)

        if step_result.status == "FAILED":
            failures.append(step.name)
            if parsed.on_error == "stop":
                break

    execution.finished_at = timezone.now()
    execution.status = Execution.Status.FAILED if failures else Execution.Status.SUCCEEDED
    execution.save(update_fields=["status", "finished_at"])

    status_msg = "com falhas" if failures else "com sucesso"
    TimelineEntry.objects.create(
        incident=incident,
        entry_type=TimelineEntry.EntryType.PLAYBOOK_EXECUTION,
        message=f"Execucao de playbook '{playbook.name}' finalizada {status_msg}",
        created_by=execution.created_by,
    )

    log_action(
        actor=execution.created_by,
        verb="playbook.execution",
        target=execution,
        meta={"status": execution.status, "failures": failures},
    )
    return execution
