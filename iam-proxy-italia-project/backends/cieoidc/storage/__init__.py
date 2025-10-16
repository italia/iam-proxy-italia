from typing import Optional

from pydantic import BaseModel

from backends.cieoidc.models.oidc_auth import (
                        OidcAuthentication,
                        OidcAuthenticationToken
)

from .interfaces.db_connection import DatabaseConnection
from .interfaces.repository import IBaseRepository
from .mongo_db.connection import MongoConnection
from .mongo_db.repository import MongoBaseRepository


class StorageFactory:

    @classmethod
    def get_repository_by_conn(cls, db_conn: DatabaseConnection, entity_type: type[BaseModel]) -> Optional[IBaseRepository]:
        """
        Factory method to obtain the repository based on the connection type and entity_type provided input.
        @param connection: database connection
        @param entity_type: type of entity to be managed
        @return: repository object
        """
        if isinstance(db_conn, MongoConnection):
            if entity_type is OidcAuthentication:
                collection = "oidc_authentication"
            elif entity_type is OidcAuthenticationToken:
                collection = "oidc_authentication_token"
            else:
                return None
            return MongoBaseRepository(db_conn, collection, entity_type)
        return None


    @classmethod
    def get_connection_by_config(cls, db_config: dict) -> Optional[DatabaseConnection]:
        if not db_config: return None

        engine = db_config.get("engine")
        extra_params = {}
        if engine == "mongodb":
            _cls = MongoConnection
            extra_params.update(db_config.get("params") or {})
        else:
            return None

        return _cls(host=db_config.get("host"), port=db_config.get("port"), driver=db_config.get("driver"),
                    username=db_config.get("username"), password=db_config.get("password"),
                    database=db_config.get("database"), tls= db_config.get("tls"), **extra_params)
