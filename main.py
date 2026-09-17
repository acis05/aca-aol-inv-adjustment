"""WSGI compatibility entrypoint for deployment platforms expecting `main:app`."""
from app import app

__all__ = ["app"]
