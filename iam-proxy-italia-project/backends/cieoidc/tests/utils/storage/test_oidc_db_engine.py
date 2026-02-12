import uuid
from datetime import datetime
import pytest
from unittest.mock import MagicMock, patch

from backends.cieoidc.storage.db_engine import OidcDbEngine
from backends.cieoidc.models.oidc_auth import OidcAuthentication


@pytest.fixture
def fake_storage():
    s = MagicMock()
    s.connect.return_value = None
    s.close.return_value = None
    s.is_connected.return_value = True
    s.add_session.return_value = 1
    s.update_session.return_value = 1
    s.get_sessions.return_value = ["session"]
    return s


@pytest.fixture
def engine(fake_storage):
    with patch(
        "backends.cieoidc.storage.db_engine.dynamic_class_loader",
        return_value=fake_storage
    ):
        return OidcDbEngine({
            "mongo": {
                "module": "x",
                "class": "y",
                "init_params": {}
            }
        })


def test_connect(engine, fake_storage):
    engine.connect()
    fake_storage.connect.assert_called_once()


def test_close(engine, fake_storage):
    engine.close()
    fake_storage.close.assert_called_once()


def test_is_connected(engine, fake_storage):
    assert engine.is_connected() is True


def test_add_session(engine):
    entity = OidcAuthentication(
        client_id="c",
        state="s",
        endpoint="e",
        provider_id="p",
        data="{}",
        provider_configuration={}
    )
    res = engine.add_session(entity)
    assert res == 1
    assert entity.id is not None


def test_update_session_no_id(engine):
    entity = MagicMock()
    entity.id = None
    assert engine.update_session(entity) == 0


def test_update_session(engine):
    entity = MagicMock()
    entity.id = str(uuid.uuid4())
    res = engine.update_session(entity)
    assert res == 1


def test_get_sessions(engine):
    res = engine.get_sessions("state")
    assert res == ["session"]


def test_prepare_for_insert_sets_dates(engine):
    entity = MagicMock()
    entity.created = None
    engine.prepare_for_insert(entity)

    assert entity.created is not None
    assert entity.modified is not None
    assert isinstance(entity.modified, datetime)
