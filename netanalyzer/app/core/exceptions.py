"""
Custom Exceptions — Application-specific error classes.

These provide meaningful error messages at the API layer
instead of generic 500 errors.
"""


class AnalysisError(Exception):
    """Raised when PCAP analysis fails (corrupted file, invalid format, etc.)."""
    pass


class RuleError(Exception):
    """Raised when a rule operation fails (invalid IP, unknown app, etc.)."""
    pass


class FlowNotFoundError(Exception):
    """Raised when a requested flow ID does not exist."""
    pass
