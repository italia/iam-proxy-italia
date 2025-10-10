import logging
import inspect
import random

from .tools.endpoints_loader import EndpointsLoader
from satosa.backends.base import BackendModule
from satosa.backends.oauth import get_metadata_desc_for_oauth_backend
from satosa.backends.openid_connect import OpenIDConnectBackend
from pyeudiw.federation.trust_chain_builder import TrustChainBuilder
from pyeudiw.federation.statements import EntityStatement, get_entity_configurations


logger = logging.getLogger(__name__)


class CieOidcBackend(BackendModule):

    def __init__(self, callback, internal_attributes, module_config, base_url, name):
        logger.debug(
            f"Initializing: {self.__class__.__name__}."
        )
        super().__init__(callback, internal_attributes, base_url, name)
        self.config = module_config
        self.endpoints = {}
        self.trust_chain = self._generate_trust_chains()
        # self.auth_callback_func = auth_callback_func
        # self.internal_attributes = internal_attributes
        # self.converter = AttributeMapper(internal_attributes)
        # self.base_url = base_url
        # self.name = name


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
            self.config, self.internal_attributes, self.base_url, self.name, self.auth_callback_func, self.converter, self.trust_chain
            )

        url_map = []

        for path, inst in el.endpoint_instances.items():
            url_map.append((f"{self.name}/{path}", inst))
        #
        # metadata_map = self.trust_evaluator.build_metadata_endpoints(
        #     self.name, self._backend_url
        # )

        # url_map.extend(metadata_map)

        for path, inst in url_map:
            self.endpoints[f"{path.split('/')[-1].replace('-', '_').replace('$', '')}"] = inst

        logger.debug(f"Loaded CIE OIDC endpoints: {url_map}")
        return url_map


    def get_metadata_desc(self):
        """
        See satosa.backends.oauth.get_metadata_desc
        :rtype: satosa.metadata_creation.description.MetadataDescription
        """
        meta = get_metadata_desc_for_oauth_backend(self.config["provider_metadata"]["issuer"], self.config)
        return meta

    def _generate_trust_chains(self) -> dict:
        '''
        private method _generate_trust_chains:
        This method generate a list of trust-chain. After create a entity statement for Trust Anchor, validate itself, and call the generate_trust_chain
        for all providers into configuration.
        Add all providers into dictionary.
        '''
        logger.debug(
            f"Entering method: {inspect.getframeinfo(inspect.currentframe()).function}. "
        )

        httpc_params = self.config["trust_chain"]["config"]["httpc_params"]

        jwt = get_entity_configurations(self.config["trust_chain"]["config"]["trust_anchor"][0], httpc_params=httpc_params)[0]

        trust_anchor_ec = EntityStatement(jwt, httpc_params=httpc_params)

        trust_anchor_ec.validate_by_itself()

        providers = self.config["providers"]

        trust_chains = dict()

        for provider_url in providers:
            try:
                trust_chains[provider_url] = CieOidcBackend.generate_trust_chain(trust_anchor_ec, provider_url, httpc_params)
            except Exception as exception:
                logger.error(f"Exception {exception} generated from this provider {provider_url}")


        return trust_chains

    @staticmethod
    def generate_trust_chain(trust_anchor_ec: EntityStatement, provider_endpoint: str, httpc_params) -> TrustChainBuilder:
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