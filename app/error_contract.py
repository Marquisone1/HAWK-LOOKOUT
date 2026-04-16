"""Standardized error response contract for API and web routes."""

from flask import jsonify
from enum import Enum


class ErrorCode(str, Enum):
    """Standard error codes."""
    # Client errors (4xx)
    INVALID_TARGET = "INVALID_TARGET"
    MISSING_FIELD = "MISSING_FIELD"
    RATE_LIMITED = "RATE_LIMITED"
    UNAUTHORIZED = "UNAUTHORIZED"
    NOT_FOUND = "NOT_FOUND"
    INVALID_JSON = "INVALID_JSON"
    
    # Server errors (5xx)
    PROVIDER_ERROR = "PROVIDER_ERROR"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# (error_code, default_message, http_status)
ERROR_MAP = {
    ErrorCode.INVALID_TARGET: ("Invalid target format", 400),
    ErrorCode.MISSING_FIELD: ("Missing required field", 400),
    ErrorCode.RATE_LIMITED: ("Rate limit exceeded", 429),
    ErrorCode.UNAUTHORIZED: ("Unauthorized", 401),
    ErrorCode.NOT_FOUND: ("Not found", 404),
    ErrorCode.INVALID_JSON: ("Invalid JSON", 400),
    ErrorCode.PROVIDER_ERROR: ("Provider returned an error", 502),
    ErrorCode.PROVIDER_UNAVAILABLE: ("Provider unavailable", 503),
    ErrorCode.INTERNAL_ERROR: ("Internal server error", 500),
}


def error_response(error_code: ErrorCode, message: str = None, **extras) -> tuple:
    """Create a standardized error response.
    
    Args:
        error_code: ErrorCode enum value
        message: Override default message (optional)
        **extras: Additional context fields (e.g., field='username', request_id=...)
    
    Returns:
        (json_response, http_status_code) tuple
    """
    default_msg, status_code = ERROR_MAP[error_code]
    msg = message or default_msg
    
    response = {
        "error": error_code.value,
        "message": msg,
    }
    
    # Add optional context fields if provided
    if extras:
        response["context"] = extras
    
    return jsonify(response), status_code


def success_response(data, **meta) -> tuple:
    """Create a standardized success response.
    
    Args:
        data: Lookup result data
        **meta: Optional metadata (lookup_id, source, timestamp, etc.)
    
    Returns:
        (json_response, 200) tuple
    """
    response = {
        "status": "success",
        "data": data,
    }
    
    if meta:
        response["meta"] = meta
    
    return jsonify(response), 200
