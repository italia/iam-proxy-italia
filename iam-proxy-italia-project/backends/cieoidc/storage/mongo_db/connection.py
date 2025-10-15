from typing import Optional
from urllib.parse import quote_plus

from pymongo import MongoClient

from ..interfaces.db_connection import DatabaseConnection


class MongoConnection(DatabaseConnection):

    def __init__(self, host: str, port: Optional[int], driver: Optional[str], username: Optional[str],
                 password: Optional[str], database: Optional[str], tls: bool = False, **kwargs):
        super().__init__(host, port, driver, username, password, database, tls)
        self._extra_params = kwargs
        self.__client = None

    def get_database_name(self) -> str:
        return self._database

    def get_handle(self) -> MongoClient:
        if self.__client is None:
            self.connect()
        return self.__client

    def connect(self) -> None:
        if self.__client is None:
            self.__client = MongoClient(self.__get_connection_uri())

    def close(self) -> None:
        if self.__client is not None:
            self.__client.close()
            self.__client = None

    def is_alive(self) -> bool:
        try:
            self.__client.admin.command('ping')
            return True
        except Exception as e:
            return False


    def __get_connection_uri(self) -> str:
        """ Build connection URI from DbConnectionConfig """
        uri = "mongodb://"
        if self._username and self._password:
            uri += f"{quote_plus(self._username)}:{quote_plus(self._password)}@"

        uri += self._host
        if self._port:
            uri += f":{self._port}"

        # uri += "/"
        # if self._database:
        #     uri += self._database

        uri += f"?tls={str(self._tls).lower()}"
        extra_params = self._extra_params.copy()
        if extra_params:
            param_str = "&".join(f"{quote_plus(str(k))}={quote_plus(str(v))}" for k, v in extra_params.items())
            uri += f"&{param_str}"
        return uri