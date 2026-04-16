"""Structured JSON logging utility for HAWK LOOKOUT."""

import json
import logging
import uuid
from datetime import datetime
from functools import wraps
from flask import request, g
from pythonjsonlogger import jsonlogger


class RequestIdFilter(logging.Filter):
    """Add request_id to all log records."""
    
    def filter(self, record):
        record.request_id = getattr(g, 'request_id', 'N/A')
        return True


def setup_json_logging(app):
    """Configure JSON logging for the Flask app."""
    # Remove default handlers
    app.logger.handlers.clear()
    
    # Add JSON formatter
    handler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        '%(timestamp)s %(level)s %(logger)s %(request_id)s %(message)s %(extra)s'
    )
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.DEBUG)
    
    # Add request ID filter to all loggers
    for logger_name in ['app', 'werkzeug', 'gunicorn']:
        logger = logging.getLogger(logger_name)
        logger.addFilter(RequestIdFilter())


def log_lookup(provider, target, query_type, status_code, duration_ms, **extras):
    """Structured log for WHOIS/DNS lookups.
    
    Args:
        provider: 'WhoisFreak', 'IP-API', 'DNS', etc.
        target: IP or domain queried
        query_type: 'ip' or 'domain'
        status_code: HTTP status (200, 400, 429, etc.)
        duration_ms: Milliseconds elapsed
        **extras: Additional fields (source_user, site_user_id, error_reason, etc.)
    """
    current_app = __import__('flask').current_app
    current_app.logger.info(
        'lookup_completed',
        extra={
            'provider': provider,
            'target': target,
            'query_type': query_type,
            'status_code': status_code,
            'duration_ms': round(duration_ms, 2),
            **extras
        }
    )


def log_error(error_code, message, status_code, **extras):
    """Structured log for errors.
    
    Args:
        error_code: 'INVALID_TARGET', 'RATE_LIMITED', 'PROVIDER_UNAVAILABLE', etc.
        message: Human-readable error message
        status_code: HTTP status
        **extras: Additional context
    """
    current_app = __import__('flask').current_app
    current_app.logger.warning(
        error_code,
        extra={
            'message': message,
            'status_code': status_code,
            **extras
        }
    )


def log_auth(event, username, status, **extras):
    """Structured log for authentication events.
    
    Args:
        event: 'login_success', 'login_failed', 'login_rate_limited', etc.
        username: Username (masked if sensitive)
        status: 'success' or 'failure'
        **extras: IP, role, reason, etc.
    """
    current_app = __import__('flask').current_app
    current_app.logger.info(
        event,
        extra={
            'username': username,
            'status': status,
            'ip': request.remote_addr,
            **extras
        }
    )


def inject_request_id():
    """Middleware to inject unique request ID."""
    g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    g.request_start_time = datetime.utcnow()
