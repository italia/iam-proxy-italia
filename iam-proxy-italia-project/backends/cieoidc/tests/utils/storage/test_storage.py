import pytest
from backends.cieoidc.storage.interfaces.storage import OidcStorage
from backends.cieoidc.models.oidc_auth import OidcAuthentication


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
