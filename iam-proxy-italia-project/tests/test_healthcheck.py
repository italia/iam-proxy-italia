import importlib.util
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml
from pymongo.errors import ConnectionFailure
from satosa.satosa_config import SATOSAConfig
from werkzeug.test import Client
from werkzeug.wrappers import Response

from healthcheck import HealthcheckMiddleware


@pytest.fixture
def mongo_client(monkeypatch):
    factory = MagicMock()
    monkeypatch.setattr("healthcheck.MongoClient", factory)
    return factory


def make_app(config=None):
    return HealthcheckMiddleware(Response("upstream", status=418), config or {})


@pytest.mark.parametrize("path, payload", [
    ("/healthz", {"status": "ok"}),
    ("/readyz", {"status": "ready"}),
])
def test_probes_without_databases(path, payload, mongo_client):
    client = Client(make_app(), Response)
    response = client.get(path)
    assert response.status_code == 200
    assert response.json == payload
    assert response.headers["Cache-Control"] == "no-store"
    head = client.head(path)
    assert head.status_code == response.status_code
    assert head.data == b""
    assert head.headers["Content-Length"] == response.headers["Content-Length"]
    mongo_client.assert_not_called()


def test_readiness_uses_enabled_modules_and_deduplicates_connections(mongo_client):
    # Storage layouts used by pyeudiw, CIE OIDC and SATOSA-oidcop.
    connection = {"url": "mongodb://wallet.example.org", "connection_params": {"username": "wallet"}}
    config = {
        "BACKEND_MODULES": [{"config": {"storage": {"mongo_db": {
            "storage": {"init_params": connection},
            "cache": {"init_params": connection},
        }}}}],
        "FRONTEND_MODULES": [{"config": {
            "user_storage": {"mongo_db": {"storage": {"init_params": connection}}},
            "credential_storage": {"mongo_db": {"storage": {"init_params": connection}}},
            "storage": {"kwargs": {"url": "mongodb://oidcop.example.org"}},
        }}],
        "MICRO_SERVICES": [{"config": {"storage": {"mongo_db": {"init_params": {
            "url": "mongodb+srv://cie.example.org", "connection_params": {"authSource": "cie"},
        }}}}}],
        "DISABLED_MODULES": [{"url": "mongodb://disabled.example.org"}],
    }
    app = make_app(config)
    mongo_client.assert_not_called()
    response = Client(app, Response).get("/readyz")
    assert response.status_code == 200
    assert mongo_client.call_count == 3
    assert [call.args[0] for call in mongo_client.call_args_list] == [
        "mongodb://wallet.example.org", "mongodb://oidcop.example.org", "mongodb+srv://cie.example.org",
    ]
    assert mongo_client.call_args_list[0].kwargs["username"] == "wallet"
    assert mongo_client.call_args_list[2].kwargs["authSource"] == "cie"
    assert mongo_client.return_value.__enter__.return_value.admin.command.call_count == 3
    assert mongo_client.return_value.__exit__.call_count == 3
    assert connection["connection_params"] == {"username": "wallet"}


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_database_failure_affects_only_readiness(method, mongo_client, caplog):
    secret = "mongodb://user:secret@db.example.org"
    mongo_client.return_value.__enter__.return_value.admin.command.side_effect = ConnectionFailure(secret)
    client = Client(make_app({"BACKEND_MODULES": [{"url": secret}]}), Response)
    response = client.open("/readyz", method=method)
    assert response.status_code == 503
    if method == "GET":
        assert response.json == {"status": "not_ready"}
    else:
        assert response.data == b""
    assert "secret" not in response.get_data(as_text=True)
    assert "secret" not in caplog.text
    mongo_client.return_value.__exit__.assert_called_once()
    mongo_client.reset_mock()
    assert client.get("/healthz").status_code == 200
    mongo_client.assert_not_called()


@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS"])
def test_probe_methods(path, method, mongo_client):
    response = Client(make_app(), Response).open(path, method=method)
    assert response.status_code == 405
    assert response.headers["Allow"] == "GET, HEAD"
    mongo_client.assert_not_called()


@pytest.mark.parametrize("path", ["/OpenID4VCI/credential", "/healthz/extra", "/readyz/extra"])
def test_other_requests_reach_satosa(path, mongo_client):
    response = Client(make_app(), Response).post(path, json={"request": "unchanged"})
    assert response.status_code == 418
    assert response.data == b"upstream"
    mongo_client.assert_not_called()


def test_resolved_project_configuration(monkeypatch):
    project = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(project)
    for path in [project / "proxy_conf.yaml", *project.glob("conf/**/*.yaml")]:
        for name in re.findall(r"!ENV\s+(\w+)", path.read_text()):
            monkeypatch.setenv(name, "test-value")
    for name in ("CIE_OIDC_BACKEND", "PYEUDIW_OPENID4VP", "PYEUDIW_OPENID4VCI", "OIDCOP"):
        monkeypatch.setenv(f"MONGO_{name}_HOST", f"mongodb://{name.lower()}.example.org")
    config = SATOSAConfig("proxy_conf.yaml")
    app = make_app(config)
    assert {url for url, params in app.connections} == {
        "mongodb://cie_oidc_backend.example.org",
        "mongodb://pyeudiw_openid4vp.example.org",
        "mongodb://pyeudiw_openid4vci.example.org",
        "mongodb://oidcop.example.org",
    }
    assert len(app.connections) == 4


def test_project_entry_point_initializes_real_satosa(tmp_path, monkeypatch):
    config_file = tmp_path / "proxy.yaml"
    config_file.write_text(yaml.safe_dump({
        "BASE": "https://iam-proxy-italia.example.org",
        "BACKEND_MODULES": [{
            "module": "satosa.backends.reflector.ReflectorBackend", "name": "reflector", "config": {},
        }],
        "FRONTEND_MODULES": [{
            "module": "satosa.frontends.ping.PingFrontend", "name": "ping", "config": {},
        }],
        "INTERNAL_ATTRIBUTES": {"attributes": {}},
        "COOKIE_STATE_NAME": "SATOSA_STATE",
        "STATE_ENCRYPTION_KEY": "test-key",
    }))
    monkeypatch.setenv("SATOSA_CONFIG", str(config_file))
    path = Path(__file__).resolve().parents[1] / "wsgi.py"
    spec = importlib.util.spec_from_file_location("project_wsgi", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = Client(module.app, Response)
    assert client.get("/healthz").json == {"status": "ok"}
    assert client.get("/readyz").json == {"status": "ready"}
    assert client.get("/ping").status_code == 200
    assert client.get("/").status_code == 404
