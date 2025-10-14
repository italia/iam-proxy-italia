from typing import Callable, Any

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.attribute_mapping import AttributeMapper

# from pyeudiw.trust.dynamic import CombinedTrustEvaluator
from .helpers.misc import get_dynamic_class



class EndpointsLoader:
    """
    A dynamic backend/frontend module.
    """

    def __init__(
            self,
            config: dict[str, Any],
            internal_attributes: dict[str, dict[str, str | list[str]]],
            base_url: str,
            name: str,
            auth_callback_func: Callable[[Context, InternalData], Response] | None = None,
            converter: AttributeMapper | None = None,
            trust_evaluator=None
            # trust_evaluator: CombinedTrustEvaluator | None = None
    ):
        """
        Create a backend/frontend dynamically.
        :param config: Configuration parameters for the module.
        :type config: dict[str, Any]
        :param internal_attributes: Internal attributes mapping.
        :type internal_attributes: dict[str, dict[str, str | list[str]]]
        :param base_url: base url of the service
        :type base_url: str
        :param name: name of the plugin
        :type name: str
        :param auth_callback_func: Function to handle authentication requests.
        :type auth_callback_func: Callable[[Context, InternalData], Response] | None
        :param converter: An instance of AttributeMapper for attribute conversion.
        :type converter: AttributeMapper | None

        :returns: The class instance
        :rtype: object
        """

        endpoints = config.get("endpoints", None)

        if not endpoints:
            raise ValueError("No endpoints configured in the OpenID4VCI config")
        
        if not isinstance(endpoints, dict):
            raise ValueError("Endpoints configuration must be a dictionary")
        
        endpoint_instances = {}
        for e in endpoints.values():
            module = e.get("module", None)
            class_name = e.get("class", None)
            routes = e.get("routes", [])
            endpoint_config = e.get("config", None)

            if module and class_name and routes:
                endpoint_class = get_dynamic_class(module, class_name)
                _handler_instance = endpoint_class(
                    endpoint_config,
                    internal_attributes,
                    base_url,
                    name,
                    auth_callback_func,
                    converter,
                    trust_evaluator
                )
                for path in routes:
                    endpoint_instances[path.lstrip("/")] = _handler_instance

        self.endpoint_instances = endpoint_instances

