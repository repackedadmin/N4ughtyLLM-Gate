"""Project error hierarchy."""


class N4ughtyLLMGateError(Exception):
    """Base error."""


class FilterRejectedError(N4ughtyLLMGateError):
    """Raised when a filter rejects request/response."""


class PolicyResolutionError(N4ughtyLLMGateError):
    """Raised when policy cannot be resolved."""


# Backward-compatible alias (historical project name).
N4ughtyLLMGateLegacyError = N4ughtyLLMGateError
