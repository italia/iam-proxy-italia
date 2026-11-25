# IAM Proxy Italia Project Configuration

See [docs/project-configuration.md](../docs/project-configuration.md) for configuration examples (uwsgi, nginx, systemd, pyff, gunicorn).

## Health and readiness

The project entry point `wsgi:app` wraps the initialized SATOSA application with two unauthenticated endpoints.
The startup scripts and uWSGI configurations use this entry point.

| Endpoint | Success | Failure |
| --- | --- | --- |
| `GET /healthz` | `200 {"status": "ok"}` when the application responds | A failed or stalled worker cannot respond successfully |
| `GET /readyz` | `200 {"status": "ready"}` when all configured MongoDB connections respond to `ping` | `503 {"status": "not_ready"}` if a database check fails |

Both endpoints support `HEAD` and disable response caching.
Readiness uses the resolved configuration of the enabled backends, frontends and microservices.
Duplicate MongoDB connections are checked once per request.
The database checks share a two-second deadline.
A deployment without MongoDB dependencies is ready once SATOSA has initialized.
These probes do not perform authentication or credential issuance flows.

With the default Docker Compose hostname:

```bash
curl https://iam-proxy-italia.example.org/healthz
curl https://iam-proxy-italia.example.org/readyz
```

Compose exposes the endpoints through nginx on HTTPS port 443.
The proxy's port 10000 speaks the uWSGI protocol.
Use `curl --cacert /path/to/ca.pem` for a private CA.
The Docker healthcheck calls `/readyz` before the existing metadata checks.
For an existing Compose installation, copy the updated project files into `Docker-compose/iam-proxy-italia-project/` and restart the proxy.
An image rebuild is not required because Compose mounts the project directory.

Run the probe tests from the repository root after installing the test dependencies:

```bash
PYTHONPATH=iam-proxy-italia-project pytest iam-proxy-italia-project/tests/test_healthcheck.py
```
