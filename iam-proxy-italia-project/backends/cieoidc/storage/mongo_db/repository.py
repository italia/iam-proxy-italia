import logging

from pymongo import MongoClient
from pymongo.errors import PyMongoError
from typing import Any, Type, List, Optional, TypeVar
from bson import ObjectId
from pydantic import BaseModel

from ..interfaces.repository import IBaseRepository
from ..mongo_db.connection import MongoConnection
from ...utils.exceptions import StorageError, StorageUnreachable

logger = logging.getLogger(__name__)

E = TypeVar("E", bound=BaseModel)


class MongoBaseRepository(IBaseRepository[E]):

    def __init__(self, conn: MongoConnection, collection: str, entity_cls: Type[E]) -> None:
        self._connection = conn
        self._client: MongoClient = conn.get_handle()
        if not self._connection.is_alive(): raise StorageUnreachable
        if not (database := conn.get_database_name()) or not collection: raise StorageError
        self._collection = self._client[database][collection]
        self._entity_cls = entity_cls

    def _to_doc(self, entity: E) -> dict[str, Any]:
        d = entity.model_dump(mode="json")
        d.pop("id", None) #auto-gen mongo _id
        return d

    def _from_doc(self, doc: dict[str, Any]) -> E:
        doc = doc.copy()
        doc["id"] = str(doc.pop("_id"))
        return self._entity_cls(**doc)

    def add(self, entity: E) -> Optional[str]:
        try:
            result = self._collection.insert_one(self._to_doc(entity))
            oid = result.inserted_id
            return str(oid)
        except PyMongoError:
            pass

    def remove(self, entity_id: str) -> bool:
        if entity_id is not str:
            return False
        oid = ObjectId(entity_id)
        try:
            result = self._collection.delete_one({"_id": oid})
            return result.deleted_count > 0
        except PyMongoError as e:
            logger.debug(e)
        return False

    def find_by_id(self, entity_id: str) -> Optional[E]:
        if entity_id is not str: return None

        oid = ObjectId(entity_id)
        doc = self._collection.find_one({"_id": oid})
        if doc is None: return None
        return self._from_doc(doc)

    def find_all(self, filters: dict[str, Any]) -> List[E]:
        cursor = self._collection.find(filters)
        return [self._from_doc(doc) for doc in cursor]
