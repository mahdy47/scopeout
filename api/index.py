"""Vercel serverless entry point.

Exposes the scopeout FastAPI ASGI app. Vercel's Python runtime auto-detects a
FastAPI application when this file exposes an ASGI object named ``app``.

The app is read-only (in-memory snapshot of real ScopeOut data) - see
``scopeout.web.seed`` for the persistence model.
"""

from scopeout.web.app import app

# Re-export so the ASGI server finds it.
__all__ = ["app"]
