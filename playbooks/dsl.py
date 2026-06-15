from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

import yaml
from automation.conditions import validate_condition_spec
from automation.input_resolution import validate_step_input_placeholders
from pydantic import BaseModel, Field, ValidationError, validator


CONTROL_BRANCH_ACTION = "control.branch"


class ParseError(Exception):
    """Raised when the playbook DSL is invalid."""


class BranchModel(BaseModel):
    name: str
    when: Any
    steps: List["StepModel"]

    @validator("name")
    def not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @validator("when")
    def validate_when_placeholders(cls, value: Any) -> Any:
        validate_condition_spec(value)
        return value


class StepModel(BaseModel):
    name: str
    action: str
    input: Dict[str, Any] = Field(default_factory=dict)
    when: Any = None
    branches: List[BranchModel] = Field(default_factory=list)
    default: List["StepModel"] = Field(default_factory=list)

    @validator("name", "action")
    def not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value

    @validator("input")
    def validate_input_placeholders(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        validate_step_input_placeholders(value)
        return value

    @validator("when")
    def validate_when_placeholders(cls, value: Any) -> Any:
        if value is not None:
            validate_condition_spec(value)
        return value

    @validator("branches", always=True)
    def validate_branch_contract(cls, value: List[BranchModel], values):
        action = values.get("action")
        if action == CONTROL_BRANCH_ACTION and not value:
            raise ValueError("control.branch exige ao menos um branch")
        if action != CONTROL_BRANCH_ACTION and value:
            raise ValueError("branches so pode ser usado com action control.branch")
        return value

    @validator("default", always=True)
    def validate_default_contract(cls, value: List["StepModel"], values):
        action = values.get("action")
        if action != CONTROL_BRANCH_ACTION and value:
            raise ValueError("default so pode ser usado com action control.branch")
        return value


class PlaybookType(str, Enum):
    INCIDENT = "incident"
    ARTIFACT = "artifact"


class ExecutionMode(str, Enum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


class TriggerEvent(str, Enum):
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    ARTIFACT_CREATED = "artifact.created"


class TriggerModel(BaseModel):
    event: TriggerEvent
    filters: Dict[str, Any] = Field(default_factory=dict)

    @validator("filters", pre=True, always=True)
    def default_filters(cls, value: Any) -> Dict[str, Any]:
        if value in (None, ""):
            return {}
        if not isinstance(value, dict):
            raise ValueError("filters deve ser um objeto")
        return value

    @validator("filters")
    def validate_filter_placeholders(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        validate_step_input_placeholders(value)
        return value


class ManualFilterTarget(str, Enum):
    INCIDENT = "incident"
    ARTIFACT = "artifact"


class ManualFilterModel(BaseModel):
    target: ManualFilterTarget
    conditions: Dict[str, Any] = Field(default_factory=dict)

    @validator("conditions", pre=True, always=True)
    def default_conditions(cls, value: Any) -> Dict[str, Any]:
        if value in (None, ""):
            return {}
        if not isinstance(value, dict):
            raise ValueError("conditions deve ser um objeto")
        return value

    @validator("conditions")
    def validate_condition_placeholders(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        validate_step_input_placeholders(value)
        return value


class PlaybookModel(BaseModel):
    name: str
    type: PlaybookType = PlaybookType.INCIDENT
    mode: ExecutionMode = ExecutionMode.AUTOMATIC
    triggers: List[TriggerModel] = Field(default_factory=list)
    filters: List[ManualFilterModel] = Field(default_factory=list)
    steps: List[StepModel]
    on_error: str = "stop"

    @validator("on_error")
    def validate_on_error(cls, value: str) -> str:
        if value not in {"continue", "stop"}:
            raise ValueError("on_error must be 'continue' or 'stop'")
        return value

    @validator("triggers", always=True)
    def validate_triggers(cls, value: List[TriggerModel], values):
        mode = values.get("mode", ExecutionMode.AUTOMATIC)
        if mode == ExecutionMode.AUTOMATIC and not value:
            raise ValueError("playbooks automaticos precisam de ao menos um trigger")
        return value

    @validator("filters", always=True)
    def validate_filters(cls, value: List[ManualFilterModel], values):
        mode = values.get("mode", ExecutionMode.AUTOMATIC)
        if mode == ExecutionMode.MANUAL and not value:
            raise ValueError("playbooks manuais precisam de ao menos um filtro")
        return value

    @validator("steps")
    def validate_unique_step_names(cls, value: List[StepModel]) -> List[StepModel]:
        seen: set[str] = set()
        duplicates: set[str] = set()

        def collect(step: StepModel) -> None:
            if step.name in seen:
                duplicates.add(step.name)
            seen.add(step.name)
            for branch in step.branches:
                for branch_step in branch.steps:
                    collect(branch_step)
            for default_step in step.default:
                collect(default_step)

        for step in value:
            collect(step)

        if duplicates:
            names = ", ".join(sorted(duplicates))
            raise ValueError(f"nomes de steps duplicados: {names}")
        return value


@dataclass
class ParsedStep:
    name: str
    action: str
    input: Dict[str, Any]
    when: Any = None
    branches: List["ParsedBranch"] | None = None
    default: List["ParsedStep"] | None = None


@dataclass
class ParsedBranch:
    name: str
    when: Any
    steps: List[ParsedStep]


@dataclass
class ParsedTrigger:
    event: str
    filters: Dict[str, Any]


@dataclass
class ParsedFilter:
    target: ManualFilterTarget
    conditions: Dict[str, Any]


@dataclass
class ParsedPlaybook:
    name: str
    type: PlaybookType
    mode: ExecutionMode
    triggers: List[ParsedTrigger]
    filters: List[ParsedFilter]
    steps: List[ParsedStep]
    on_error: str

    def all_steps(self) -> List[ParsedStep]:
        collected: List[ParsedStep] = []

        def collect(step: ParsedStep) -> None:
            collected.append(step)
            for branch in step.branches or []:
                for branch_step in branch.steps:
                    collect(branch_step)
            for default_step in step.default or []:
                collect(default_step)

        for step in self.steps:
            collect(step)
        return collected


def _load_data(data: Any) -> Any:
    if isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return yaml.safe_load(data)
    return data


def _parse_step(step: StepModel) -> ParsedStep:
    return ParsedStep(
        name=step.name,
        action=step.action,
        input=step.input,
        when=step.when,
        branches=[
            ParsedBranch(
                name=branch.name,
                when=branch.when,
                steps=[_parse_step(branch_step) for branch_step in branch.steps],
            )
            for branch in step.branches
        ],
        default=[_parse_step(default_step) for default_step in step.default],
    )


def parse_playbook(data: Any) -> ParsedPlaybook:
    raw = _load_data(data)
    try:
        validated = PlaybookModel.model_validate(raw)
    except ValidationError as exc:
        raise ParseError(exc.errors())
    steps = [_parse_step(step) for step in validated.steps]
    triggers = [
        ParsedTrigger(event=trigger.event.value, filters=trigger.filters)
        for trigger in validated.triggers
    ]
    filters = [
        ParsedFilter(target=manual_filter.target, conditions=manual_filter.conditions)
        for manual_filter in validated.filters
    ]
    return ParsedPlaybook(
        name=validated.name,
        type=validated.type,
        mode=validated.mode,
        triggers=triggers,
        filters=filters,
        steps=steps,
        on_error=validated.on_error,
    )
