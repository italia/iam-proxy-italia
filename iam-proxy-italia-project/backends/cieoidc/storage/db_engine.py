import uuid

from typing import Any
from datetime import datetime, timezone
from backends.cieoidc.models.oidc_auth import OidcAuthentication
from backends.cieoidc.storage.interfaces.storage import OidcStorage
from backends.cieoidc.utils.helpers.misc import dynamic_class_loader


class OidcDbEngine(OidcStorage):

    def __init__(self, config: dict) -> None:
        self._storages: list = []
        for db_name, db_conf in config.items():
            if db_conf:
                storage_instance = dynamic_class_loader(
                    db_conf["module"],
                    db_conf["class"],
                    db_conf.get("init_params", {}),
                )
                if storage_instance:
                    self._storages.append(storage_instance)

    def __call_storages(self, method: str):
        for storage in self._storages:
            try:
                attr = getattr(storage, method)
                if callable(attr):
                    yield attr
                yield None
            except AttributeError:
                yield None

    def __write(self, method, *args, **kwargs) -> Any:
        updates = 0
        for _callable in self.__call_storages(method):
            if _callable is None: continue
            updates += _callable(*args, **kwargs)
        return updates

    def __find(self, method, *args, **kwargs) -> Any:
        result = None
        for _callable in self.__call_storages(method):
            if _callable is None: continue
            res = _callable(*args, **kwargs)
            if res is None: continue
            result = res
            break
        return result

    def connect(self) -> None:
        for _callable in self.__call_storages(self.connect.__name__):
            if _callable is None:
                continue
            _callable()

    def close(self) -> None:
        for _callable in self.__call_storages(self.close.__name__):
            if _callable is None:
                continue
            _callable()

    def is_connected(self) -> bool:
        alive = False
        for _callable in self.__call_storages(self.is_connected.__name__):
            if _callable is None:
                continue
            alive |= _callable()
        return alive


    def add_session(self, entity: OidcAuthentication) -> int:
        self.prepare_for_insert(entity)
        entity.id = str(uuid.uuid4())
        return self.__write(self.add_session.__name__, entity)

    def update_session(self, entity: OidcAuthentication) -> int:
        if not entity.id:
            return 0
        self.prepare_for_insert(entity)
        return self.__write(self.update_session.__name__, entity)

    def get_sessions(self, state: str) -> list[OidcAuthentication]:
        return self.__find(self.get_sessions.__name__, state)

    def prepare_for_insert(self, auth_entity: OidcAuthentication):
        now = datetime.now(timezone.utc)
        if auth_entity.created is None:
            auth_entity.created = now
        auth_entity.modified = now