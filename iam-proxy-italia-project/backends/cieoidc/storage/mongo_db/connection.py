from typing import Optional
from urllib.parse import quote_plus

from pymongo import MongoClient

from backends.cieoidc.storage.entities import DbConnectionConfig
from backends.cieoidc.storage.interfaces.db_connection import DatabaseConnection


class MongoConnection(DatabaseConnection):


    def __init__(self, uri: str):
        """
        Constructor to be considered as private one
        """
        self._client = None
        self._uri = uri

    @classmethod
    def from_config(cls, db_config: DbConnectionConfig) -> Optional["MongoConnection"]:
        if db_config is None:
            return None
        _uri = cls._uri_from_config(db_config)
        return cls(_uri)

    def get_handle(self) -> MongoClient:
        if self._client is None:
            self.connect()
        return self._client

    def connect(self) -> None:
        if self._client is None:
            self._client = MongoClient(self._uri)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def is_connected(self) -> bool:
        try:
            self._client.admin.command('ping')
            return True
        except Exception as e:
            return False

    @classmethod
    def _uri_from_config(cls, db_config: DbConnectionConfig) -> str:
        """ Build connection URI from DbConnectionConfig """
        uri = "mongodb://"
        if db_config.username and db_config.password:
            uri += f"{quote_plus(db_config.username)}:{quote_plus(db_config.password)}@"

        uri += db_config.host
        if db_config.port:
            uri += f":{db_config.port}"

        uri += "/"
        if db_config.database:
            uri += db_config.database

        uri += f"?tls={str(db_config.tls).lower()}"
        extra_params = db_config.params.copy()
        if extra_params:
            param_str = "&".join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k, v in extra_params.items())
            uri += f"&{param_str}"
        return uri