from abc import ABC, abstractmethod
from typing import Any, Optional


class DatabaseConnection(ABC):

    def __init__(self, host: str, port: int, driver: Optional[str], username: Optional[str],
                 password: Optional[str], database: str, tls: bool = False):
        self._database = database
        self._host = host
        self._port = port
        self._driver = driver
        self._username = username
        self._password = password
        self._tls = tls

    @abstractmethod
    def get_database_name(self) -> str:
        ...

    @abstractmethod
    def get_handle(self) -> Any:
        ...

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def is_alive(self) -> bool:
        ...
