"""Lotus SDK exceptions."""
from __future__ import annotations


class LotusError(Exception):
    """Base exception for all Lotus SDK errors."""

    def __init__(self, message: str, status_code: int = 0, response_body: str = ""):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)


class LotusConnectionError(LotusError):
    """Cannot connect to the Lotus server."""
    pass


class LotusAPIError(LotusError):
    """Server returned an error response (4xx or 5xx)."""
    pass


class LotusNotFoundError(LotusAPIError):
    """Resource not found (404)."""
    pass


class LotusValidationError(LotusAPIError):
    """Request validation failed (422)."""
    pass


class LotusTimeoutError(LotusError):
    """Request timed out."""
    pass
