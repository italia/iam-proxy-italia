from abc import ABC, abstractmethod
from typing import Any

from backends.cieoidc.storage.entities import DbConnectionConfig


class DatabaseConnection(ABC):

    @classmethod
    @abstractmethod
    def from_config(cls, db_config: DbConnectionConfig):
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
    def is_connected(self) -> bool:
        ...
