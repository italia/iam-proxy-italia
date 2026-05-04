import logging
import inspect
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Optional

from satosa.backends.base import BackendModule
from satosa.backends.oauth import get_metadata_desc_for_oauth_backend

from .utils.endpoints_loader import EndpointsLoader
from .storage.db_engine import OidcDbEngine
from .models.trust_chain_cache import TrustChainCache

from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.statements import EntityStatement, get_entity_configurations

from .utils.exceptions import TrustChainNotFoundError


logger = logging.getLogger(__name__)


def _trust_chain_from_cache(cached: TrustChainCache):
    """
    Build a minimal trust-chain-like object from TrustChainCache.
    Has .subject and .subject_configuration.payload as required by authorization endpoint.
    """
    wrapper = SimpleNamespace()
    wrapper.subject = cached.provider_url
    wrapper.subject_configuration = SimpleNamespace(payload=cached.payload)
    return wrapper


def _is_cache_expired(cached: TrustChainCache, now=None) -> bool:
    """Return True if the cached payload is expired (exp in the past)."""
    exp = cached.exp or cached.payload.get("exp")
    if exp is None:
        return False
    t = now if now is not None else time.time()
    return t >= exp


class TrustChainResolver:
    """
    Resolves trust chains from cache or builds them on-demand via discovery.
    When a provider is requested but not in the cache (e.g. startup failed),
    discovery is performed and the resulting trust chain is stored for reuse.
    """

    def __init__(self, trust_chains: dict, build_callback):
        """
        :param trust_chains: Dict of provider_url -> TrustChainBuilder (mutated when new chains are built)
        :param build_callback: Callable(provider_url) -> TrustChainBuilder; raises TrustChainNotFoundError on failure
        """
        self._chains = trust_chains
        self._build = build_callback

    def __contains__(self, key):
        return key in self._chains

    def __getitem__(self, key):
        return self._chains[key]

    def keys(self):
        return self._chains.keys()

    def get_or_build(self, provider_url: str) -> TrustChainBuilder:
        """Get trust chain from cache, or discover and store it on-demand."""
        for key in (
            provider_url,
            provider_url.rstrip("/"),
            provider_url + "/" if not provider_url.endswith("/") else None,
        ):
            if key and key in self._chains:
                return self._chains[key]
        return self._build(provider_url)


class CieOidcBackend(BackendModule):

    def __init__(self, callback, internal_attributes, module_config, base_url, name):
        logger.debug(
            f"Initializing: {self.__class__.__name__}."
        )
        super().__init__(callback, internal_attributes, base_url, name)
        self.config = module_config
        self.endpoints = {}
        self._trust_anchor_ec = None
        self.trust_chain = self._generate_trust_chains()
        self._trust_chain_resolver = TrustChainResolver(
            self.trust_chain,
            self.get_or_build_trust_chain,
        )
        metadata = self.config.get("metadata", {}).get("openid_relying_party", {})
        self._client_id = metadata.get("client_id") or f"{base_url}/{name}"

    def start_auth(self, context, internal_request):
        """
        This is the start up function of the backend authorization.

        :type context: satosa.context.Context
        :type internal_request: satosa.internal.InternalData
        :rtype satosa.response.Response

        :param context: the request context
        :param internal_request: Information about the authorization request
        :return: response
        """
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
            f"Params [metadata: {context}, conf: {internal_request}]"
        )

        authorization_endpoint = self.endpoints.get("authorization")
        if not authorization_endpoint:
            raise ValueError("No authorization endpoint configured in the CieOidc backend")

        return authorization_endpoint(context)

    def register_endpoints(self):
        el = EndpointsLoader(
            self.config,
            self.internal_attributes,
            self.base_url,
            self.name,
            self.auth_callback_func,
            self.converter,
            self._trust_chain_resolver,
        )

        url_map = []

        for path, inst in el.endpoint_instances.items():
            url_map.append((f"{self.name}/{path}", inst))

        for path, inst in url_map:
            key = path.split('/')[-1].replace('-', '_').replace('$', '')
            self.endpoints[key] = inst

        logger.debug(f"Loaded CIE OIDC endpoints: {url_map}")
        return url_map

    def get_metadata_desc(self):
        """
        See satosa.backends.oauth.get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        meta = get_metadata_desc_for_oauth_backend(self._client_id, self.config)
        return meta

    def _get_storage(self) -> Optional[OidcDbEngine]:
        """Create and return storage engine; connect if needed. Returns None if no storage configured."""
        if getattr(self, "_storage_engine", None) is not None:
            return self._storage_engine
        storage_config = self.config.get("storage") or {}
        if not storage_config:
            return None
        try:
            engine = OidcDbEngine(storage_config)
            engine.connect()
            self._storage_engine = engine
            return engine
        except Exception as e:
            logger.warning("Could not initialize storage for trust chain persistence: %s", e)
            return None

    def _store_trust_chain(self, chain, provider_url: str) -> None:
        """Persist trust chain to database if storage is available."""
        engine = self._get_storage()
        if engine is None:
            return
        try:
            payload = chain.subject_configuration.payload
            exp = payload.get("exp")
            cached = TrustChainCache(
                provider_url=provider_url,
                payload=payload,
                exp=exp,
                created=datetime.now(timezone.utc),
            )
            engine.add_or_update_trust_chain(cached)
        except Exception as e:
            logger.warning("Could not persist trust chain for %s: %s", provider_url, e)

    def _generate_trust_chains(self) -> dict:
        '''
        private method _generate_trust_chains:
        Tries to load trust chains from DB first; for missing or expired entries,
        fetches Trust Anchor, builds chains, and persists them to DB.
        '''
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        )

        httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
        providers = self.config["providers"]
        trust_chains = dict()
        trust_anchor_ec = None

        for provider_url in providers:
            # Try load from DB
            engine = self._get_storage()
            if engine:
                cached = engine.get_trust_chain_by_provider(provider_url)
                if cached and not _is_cache_expired(cached):
                    chain = _trust_chain_from_cache(cached)
                    trust_chains[provider_url] = chain
                    normalized = provider_url.rstrip("/") if provider_url.endswith("/") else provider_url + "/"
                    if normalized != provider_url:
                        trust_chains[normalized] = chain
                    continue

            # Build via discovery
            try:
                if trust_anchor_ec is None:
                    ta_url = self.config["trust_chain"]["config"]["trust_anchor"][0]
                    jwt = get_entity_configurations(ta_url, httpc_params=httpc_params)[0]
                    trust_anchor_ec = EntityStatement(jwt, httpc_params=httpc_params)
                    trust_anchor_ec.validate_by_itself()
                    self._trust_anchor_ec = trust_anchor_ec

                chain = CieOidcBackend.generate_trust_chain(
                    trust_anchor_ec, provider_url, httpc_params
                )
                trust_chains[provider_url] = chain
                normalized = provider_url.rstrip("/") if provider_url.endswith("/") else provider_url + "/"
                if normalized != provider_url:
                    trust_chains[normalized] = chain
                self._store_trust_chain(chain, provider_url)
            except Exception as exception:
                logger.error(
                    "Exception %s generated from this provider %s",
                    exception,
                    provider_url,
                )

        return trust_chains

    @staticmethod
    def generate_trust_chain(
        trust_anchor_ec: EntityStatement, provider_endpoint: str, httpc_params
    ) -> TrustChainBuilder:
        '''
        method _generate_trust_chain:
        This method generate a TrustChain Object from provider endpoint and Trust Anchor.
        After the creation, start and validate the Trust Chain.

        '''
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        )

        trust_chain = TrustChainBuilder(
            subject=provider_endpoint,
            trust_anchor=trust_anchor_ec.sub,
            trust_anchor_configuration=trust_anchor_ec,
            httpc_params=httpc_params,
        )

        trust_chain.start()
        trust_chain.apply_metadata_policy()
        return trust_chain

    def _ensure_trust_anchor(self) -> EntityStatement:
        """Return cached trust anchor EC, or fetch and cache it."""
        if self._trust_anchor_ec is None:
            httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
            ta_url = self.config["trust_chain"]["config"]["trust_anchor"][0]
            jwt = get_entity_configurations(ta_url, httpc_params=httpc_params)[0]
            self._trust_anchor_ec = EntityStatement(jwt, httpc_params=httpc_params)
            self._trust_anchor_ec.validate_by_itself()
        return self._trust_anchor_ec

    def get_or_build_trust_chain(self, provider_url: str) -> TrustChainBuilder:
        """
        Get trust chain from cache, or from DB, or discover and build it on-demand.
        Newly built chains are stored in memory and in the database.
        """
        providers = self.config.get("providers", [])
        provider_variants = (provider_url, provider_url.rstrip("/"), provider_url + "/" if not provider_url.endswith("/") else None)
        if not any(p in providers for p in provider_variants if p):
            raise TrustChainNotFoundError(
                f"The identity provider '{provider_url}' is not in the configured providers list. "
                f"Configured: {', '.join(providers)}."
            ) from None

        # Try load from DB (in-memory cache already checked by TrustChainResolver)
        engine = self._get_storage()
        if engine:
            cached = engine.get_trust_chain_by_provider(provider_url)
            if cached and not _is_cache_expired(cached):
                chain = _trust_chain_from_cache(cached)
                self.trust_chain[provider_url] = chain
                normalized = provider_url.rstrip("/") if provider_url.endswith("/") else provider_url + "/"
                if normalized != provider_url:
                    self.trust_chain[normalized] = chain
                logger.info("Trust chain loaded from DB for provider %s", provider_url)
                return chain

        logger.info(
            "Trust chain not in cache; performing on-demand discovery for provider %s",
            provider_url,
        )
        httpc_params = self.config["trust_chain"]["config"]["httpc_params"]
        trust_anchor_ec = self._ensure_trust_anchor()

        chain = CieOidcBackend.generate_trust_chain(
            trust_anchor_ec, provider_url, httpc_params
        )
        self.trust_chain[provider_url] = chain
        normalized = provider_url.rstrip("/") if provider_url.endswith("/") else provider_url + "/"
        if normalized != provider_url:
            self.trust_chain[normalized] = chain
        self._store_trust_chain(chain, provider_url)
        logger.info("Trust chain built and stored for provider %s", provider_url)
        return chain
