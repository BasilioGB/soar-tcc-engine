class AutomationError(Exception):
    """Base exception for automation failures."""


class StepExecutionError(AutomationError):
    def __init__(self, step_name: str, message: str):
        super().__init__(f"Step {step_name} failed: {message}")
        self.step_name = step_name
        self.message = message
