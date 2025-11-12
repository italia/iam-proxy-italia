from abc import ABC, abstractmethod

from backends.cieoidc.models.oidc_auth import OidcAuthentication


class OidcStorage(ABC):

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def close(self) -> None:
        ...

    @abstractmethod
    def is_connected(self) -> bool:
        ...

    @abstractmethod
    def add_session(self, entity: OidcAuthentication) -> int:
        ...

    @abstractmethod
    def update_session(self, entity: OidcAuthentication) -> int:
        ...

    @abstractmethod
    def get_sessions(self, state: str) -> list[OidcAuthentication]:
        ...
