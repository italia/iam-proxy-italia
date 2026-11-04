import pytest
from backends.cieoidc.storage.interfaces.storage import OidcStorage
from backends.cieoidc.models.oidc_auth import OidcAuthentication


def _session(state: str, **kwargs) -> OidcAuthentication:
    return OidcAuthentication(
        client_id="client",
        state=state,
        endpoint="https://op.example/authorization",
        data="{}",
        provider_configuration={},
        **kwargs,
    )


def test_oidc_storage_is_abstract():
    with pytest.raises(TypeError):
        OidcStorage()


class IncompleteStorage(OidcStorage):
    def connect(self):
        pass


def test_incomplete_storage_cannot_be_instantiated():
    with pytest.raises(TypeError):
        IncompleteStorage()


class DummyStorage(OidcStorage):

    def connect(self) -> None:
        self._connected = True

    def close(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return getattr(self, "_connected", False)

    def add_session(self, entity: OidcAuthentication) -> int:
        return 1

    def update_session(self, entity: OidcAuthentication) -> int:
        return 1

    def get_sessions(self, state: str) -> list[OidcAuthentication]:
        return []


def test_dummy_storage_can_be_instantiated():
    storage = DummyStorage()
    assert isinstance(storage, OidcStorage)


def test_dummy_storage_methods_contract():
    storage = DummyStorage()

    storage.connect()
    assert storage.is_connected() is True

    storage.close()
    assert storage.is_connected() is False

    result_add = storage.add_session(entity=None)
    assert isinstance(result_add, int)

    result_update = storage.update_session(entity=None)
    assert isinstance(result_update, int)

    result_get = storage.get_sessions("state123")
    assert isinstance(result_get, list)


class MemoryStorage(OidcStorage):

    def __init__(self):
        self.rows: list[OidcAuthentication] = []

    def connect(self) -> None:
        pass

    def close(self) -> None:
        pass

    def is_connected(self) -> bool:
        return True

    def add_session(self, entity: OidcAuthentication) -> int:
        self.rows.append(entity)
        return 1

    def update_session(self, entity: OidcAuthentication) -> int:
        return 1

    def get_sessions(self, state: str) -> list[OidcAuthentication]:
        return [row for row in self.rows if row.state == state]


def test_consume_session_is_single_use():
    storage = MemoryStorage()
    storage.add_session(_session("state-1"))

    first = storage.consume_session("state-1")
    assert first is not None
    assert first.completed is True
    assert storage.consume_session("state-1") is None


def test_consume_session_rejects_session_that_already_has_a_token():
    storage = MemoryStorage()
    storage.add_session(_session("state-1", access_token="already-issued"))
    assert storage.consume_session("state-1") is None
