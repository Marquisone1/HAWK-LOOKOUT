"""
Gunicorn / WSGI entry point.

Usage (production):
    gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app

Usage (local dev):
    flask --app wsgi:app run --debug
"""
from app import create_app

app = create_app()
