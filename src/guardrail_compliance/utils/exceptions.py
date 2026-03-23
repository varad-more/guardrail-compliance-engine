class GuardrailComplianceError(Exception):
    """Base project error."""


class ParserError(GuardrailComplianceError):
    """Raised when an IaC parser cannot understand a file."""


class PolicyValidationError(GuardrailComplianceError):
    """Raised when a policy document is invalid."""


class BedrockEvaluationError(GuardrailComplianceError):
    """Raised when Bedrock evaluation fails."""
