"""WSGI health and readiness probes for the initialized SATOSA application."""

import json
import logging

from pymongo import MongoClient, timeout
from pymongo.errors import PyMongoError


logger = logging.getLogger(__name__)


def _mongo_connections(config):
    """Find MongoDB connections in the resolved configuration of active modules."""
    if isinstance(config, dict):
        url = config.get("url")
        if isinstance(url, str) and url.startswith(("mongodb://", "mongodb+srv://")):
            yield url, dict(config.get("connection_params") or {})
        for value in config.values():
            yield from _mongo_connections(value)
    elif isinstance(config, list):
        for value in config:
            yield from _mongo_connections(value)


class HealthcheckMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.connections = []
        for group in ("BACKEND_MODULES", "FRONTEND_MODULES", "MICRO_SERVICES"):
            for connection in _mongo_connections(config.get(group, [])):
                if connection not in self.connections:
                    self.connections.append(connection)

    def _is_ready(self):
        try:
            # One deadline covers every database check in this request.
            with timeout(2):
                for url, params in self.connections:
                    options = dict(params)
                    options.update(
                        connect=False,
                        connectTimeoutMS=1000,
                        serverSelectionTimeoutMS=1000,
                        socketTimeoutMS=1000,
                    )
                    # Create clients in the worker, after uWSGI forks.
                    with MongoClient(url, **options) as client:
                        client.admin.command("ping")
        except (PyMongoError, ValueError) as error:
            # Driver errors may contain connection URLs or credentials.
            logger.warning("Readiness MongoDB check failed (%s)", type(error).__name__)
            return False
        return True

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path not in ("/healthz", "/readyz"):
            return self.app(environ, start_response)

        method = environ.get("REQUEST_METHOD", "GET")
        headers = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
        if method not in ("GET", "HEAD"):
            status = "405 Method Not Allowed"
            payload = {"status": "method_not_allowed"}
            headers.append(("Allow", "GET, HEAD"))
        elif path == "/healthz":
            status = "200 OK"
            payload = {"status": "ok"}
        elif self._is_ready():
            status = "200 OK"
            payload = {"status": "ready"}
        else:
            status = "503 Service Unavailable"
            payload = {"status": "not_ready"}

        body = json.dumps(payload).encode("utf-8")
        headers.append(("Content-Length", str(len(body))))
        start_response(status, headers)
        return [b"" if method == "HEAD" else body]
