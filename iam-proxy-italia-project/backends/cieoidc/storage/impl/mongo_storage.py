import logging

from pymongo import MongoClient
from pymongo.errors import InvalidOperation, PyMongoError

from bson import ObjectId
from pydantic import BaseModel
from typing import Optional, Any, List, TypeVar

from backends.cieoidc.models.oidc_auth import OidcAuthentication
from backends.cieoidc.models.user import OidcUser
from backends.cieoidc.storage.interfaces.storage import OidcStorage

E = TypeVar("E", bound=BaseModel)

logger = logging.getLogger(__name__)


class MongoStorage(OidcStorage):

    def __init__(self, conf: dict, url: str, connection_params: dict = None):
        self._db_name = conf.get("db_name")
        self._data_ttl = conf.get("data_ttl")
        self._url = url
        self._username = (connection_params or {}).get("username")
        self._password = (connection_params or {}).get("password")
        self._auth_collection = conf.get("db_auth_collection")
        self._token_collection = conf.get("db_token_collection")
        self._user_collection = conf.get("db_user_collection")
        self.__client = None

    @property
    def _db(self):
        if self.__client is not None:
            return self.__client[self._db_name]
        return None

    def connect(self) -> None:
        if self.__client is None:
            self.__client = MongoClient(self._url, username=self._username, password=self._password)

    def close(self) -> None:
        if self.__client is not None:
            self.__client.close()
            self.__client = None

    def is_connected(self) -> bool:
        if not self.__client:
            return False
        try:
            self.__client.server_info()
        except InvalidOperation:
            return False
        return True

    def _to_doc(self, entity: E, include_unset=True) -> dict[str, Any]:
        d = entity.model_dump(mode="json", exclude_unset=not include_unset)
        d.pop("id", None)  # auto-gen mongo _id
        return d

    def _from_doc(self, doc: dict[str, Any], entity_cls) -> E:
        doc = doc.copy()
        doc["id"] = str(doc.pop("_id"))
        return entity_cls(**doc)

    def _add(self, collection: str, entity: E) -> Optional[str]:
        try:
            result = self._db[collection].insert_one(self._to_doc(entity))
            oid = result.inserted_id
            return str(oid)
        except PyMongoError:
            return None

    def _update(self, collection: str, entity_id: str, entity: E, override=False) -> Optional[bool]:
        if not entity_id or not isinstance(entity_id, str):
            return False

        if not (to_update := self._to_doc(entity, include_unset=override)):
            return False

        try:
            result = self._db[collection].update_one(
                {"_id": ObjectId(entity_id)},
                {"$set": to_update}
            )
        except PyMongoError as e:
            logger.debug(e)
            return None
        return result.modified_count > 0

    def _remove(self, collection: str, entity_id: str) -> Optional[bool]:
        if entity_id is not str:
            return False
        oid = ObjectId(entity_id)
        try:
            result = self._db[collection].delete_one({"_id": oid})
            return result.deleted_count > 0
        except PyMongoError as e:
            logger.debug(e)
            return None

    def _find_by_id(self, collection: str, entity_id: str, entity_cls: type[BaseModel]) -> Optional[E]:
        if entity_id is not str: return None

        oid = ObjectId(entity_id)
        doc = self._db[collection].find_one({"_id": oid})
        if doc is None: return None
        return self._from_doc(doc, entity_cls)

    def _find_all(self, collection: str, filters: dict[str, Any], entity_cls: type[BaseModel]) -> List[E]:
        cursor = self._db[collection].find(filters)
        return [self._from_doc(doc, entity_cls) for doc in cursor]

    def add_oidc_auth(self, entity: OidcAuthentication) -> int:
        if self._add(self._auth_collection, entity) is not None:
            return 1
        return 0

    def update_oidc_auth(self, entity_id: str, entity: OidcAuthentication) -> int:
        if self._update(self._auth_collection, entity_id, entity) is not None:
            return 1
        return 0

    # def add_oidc_token(self, entity: OidcAuthenticationToken) -> int:
    #     if self._add(self._token_collection, entity) is not None:
    #         return 1
    #     return 0

    def add_oidc_user(self, entity: OidcUser) -> int:
        if self._add(self._user_collection, entity) is not None:
            return 1
        return 0

    def get_authentications(self, state: str) -> list[OidcAuthentication]:
        return self._find_all(self._auth_collection, {"state": state}, OidcAuthentication)

