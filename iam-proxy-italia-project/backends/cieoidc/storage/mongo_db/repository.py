from typing import Any, Type, List, Optional, TypeVar

from bson import ObjectId
from pydantic import BaseModel

from ..interfaces.repository import IBaseRepository
from ..mongo_db.connection import MongoConnection

E = TypeVar("E", bound=BaseModel)


class MongoBaseRepository(IBaseRepository[E]):

    def __init__(self, conn: MongoConnection, database, collection: str, entity_cls: Type[E]) -> None:
        self._connection = conn
        self._client = conn.get_handle()
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
        result = self._collection.insert_one(self._to_doc(entity))
        oid = result.inserted_id
        return str(oid)

    def remove(self, entity_id: str) -> bool:
        try:
            oid = ObjectId(entity_id)
        except Exception:
            return False

        result = self._collection.delete_one({"_id": oid})
        return result.deleted_count > 0

    def find_by_id(self, entity_id: str) -> Optional[E]:
        try:
            oid = ObjectId(entity_id)
        except Exception:
            oid = entity_id

        doc = self._collection.find_one({"_id": oid})
        if doc is None:
            return None
        return self._from_doc(doc)

    def find_all(self, filters: dict[str, Any]) -> List[E]:
        cursor = self._collection.find(filters)
        return [self._from_doc(doc) for doc in cursor]
