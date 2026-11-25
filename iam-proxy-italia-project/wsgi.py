"""Project WSGI entry point with health and readiness probes."""

from satosa.wsgi import app as satosa_app, satosa_config

from healthcheck import HealthcheckMiddleware


app = HealthcheckMiddleware(satosa_app, satosa_config)
