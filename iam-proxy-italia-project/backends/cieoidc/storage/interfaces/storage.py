from abc import ABC, abstractmethod

from backends.cieoidc.models.oidc_auth import OidcAuthentication, OidcAuthenticationToken
from backends.cieoidc.models.user import OidcUser


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
    def add_oidc_auth(self, entity: OidcAuthentication) -> int:
        ...

    @abstractmethod
    def add_oidc_token(self, entity: OidcAuthenticationToken) -> int:
        ...

    @abstractmethod
    def add_oidc_user(self, entity: OidcUser) -> int:
        ...

    @abstractmethod
    def get_authentications(self, state: str) -> list[OidcAuthentication]:
        ...
