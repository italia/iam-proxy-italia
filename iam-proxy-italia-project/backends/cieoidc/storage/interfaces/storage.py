from abc import ABC, abstractmethod
from typing import Optional

from backends.cieoidc.models.oidc_auth import OidcAuthentication
from backends.cieoidc.models.trust_chain_cache import TrustChainCache


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

    def get_trust_chain_by_provider(self, provider_url: str) -> Optional[TrustChainCache]:
        """Get cached trust chain by provider URL. Return None if not found or not supported."""
        return None

    def add_or_update_trust_chain(self, entity: TrustChainCache) -> int:
        """Upsert trust chain. Return 1 on success, 0 on failure or if not supported."""
        return 0
