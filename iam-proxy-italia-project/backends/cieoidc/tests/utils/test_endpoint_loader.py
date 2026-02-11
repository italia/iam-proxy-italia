import pytest
from unittest.mock import patch, MagicMock

from satosa.context import Context
from satosa.internal import InternalData
from satosa.response import Response
from satosa.attribute_mapping import AttributeMapper

from backends.cieoidc.utils.endpoints_loader import EndpointsLoader

@pytest.fixture
def base_params():
    return {
        "internal_attributes": {},
        "base_url": "http://example.org",
        "name": "test-backend",
        "auth_callback_func": MagicMock(spec=lambda x, y: Response("ok")),
        "converter": MagicMock(spec=AttributeMapper),
        "trust_evaluator": MagicMock(),
    }

def test_init_without_endpoints_raises():
    with pytest.raises(ValueError, match="No endpoints configured"):
        EndpointsLoader(
            config={},
            internal_attributes={},
            base_url="http://example.org",
            name="test",
        )

def test_init_with_invalid_endpoints_type_raises():
    with pytest.raises(ValueError, match="Endpoints configuration must be a dictionary"):
        config_example={
            "endpoints": [1,2,3]
        }
        EndpointsLoader(
            config=config_example,
            internal_attributes={},
            base_url="http://example.org",
            name="test",
        )

@patch("backends.cieoidc.utils.endpoints_loader.get_dynamic_class")
def test_endpoint_loader_creates_instances(mock_get_class, base_params):
    mock_endpoint_instance = MagicMock()
    mock_endpoint_class = MagicMock(return_value=mock_endpoint_instance)
    mock_get_class.return_value = mock_endpoint_class

    config = {
        "endpoints": {
            "authorization": {
                "module": "fake.module",
                "class": "FakeEndpoint",
                "routes": ["/authorize", "/auth"],
                "config": {"a": 1},
            }
        }
    }

    loader = EndpointsLoader(
        config=config,
        internal_attributes=base_params["internal_attributes"],
        base_url=base_params["base_url"],
        name=base_params["name"],
        auth_callback_func=base_params["auth_callback_func"],
        converter=base_params["converter"],
        trust_evaluator=base_params["trust_evaluator"],
    )

    # get_dynamic_class chiamato correttamente
    mock_get_class.assert_called_once_with("fake.module", "FakeEndpoint")

    # istanza endpoint creata
    mock_endpoint_class.assert_called_once()

    # routes normalizzate
    assert "authorize" in loader.endpoint_instances
    assert "auth" in loader.endpoint_instances

    # stessa istanza per entrambe le route
    assert loader.endpoint_instances["authorize"] is mock_endpoint_instance
    assert loader.endpoint_instances["auth"] is mock_endpoint_instance

@patch("backends.cieoidc.utils.endpoints_loader.get_dynamic_class")
def test_endpoint_with_missing_fields_is_skipped(mock_get_class, base_params):
    config = {
        "endpoints": {
            "invalid": {
                "module": "fake.module",
                "class": None,
                "routes": ["/invalid"],
            }
        }
    }

    loader = EndpointsLoader(
        config=config,
        internal_attributes=base_params["internal_attributes"],
        base_url=base_params["base_url"],
        name=base_params["name"],
        auth_callback_func=base_params["auth_callback_func"],
        converter=base_params["converter"],
        trust_evaluator=base_params["trust_evaluator"],
    )

    # nessun endpoint caricato
    assert loader.endpoint_instances == {}
    mock_get_class.assert_not_called()

@patch("backends.cieoidc.utils.endpoints_loader.get_dynamic_class")
def test_routes_without_leading_slash(mock_get_class, base_params):
    mock_endpoint_instance = MagicMock()
    mock_get_class.return_value = MagicMock(return_value=mock_endpoint_instance)

    config = {
        "endpoints": {
            "test": {
                "module": "fake.module",
                "class": "FakeEndpoint",
                "routes": ["token"],
                "config": {},
            }
        }
    }

    loader = EndpointsLoader(
        config=config,
        internal_attributes=base_params["internal_attributes"],
        base_url=base_params["base_url"],
        name=base_params["name"],
        auth_callback_func=base_params["auth_callback_func"],
        converter=base_params["converter"],
        trust_evaluator=base_params["trust_evaluator"],
    )

    assert "token" in loader.endpoint_instances

@patch("backends.cieoidc.utils.endpoints_loader.get_dynamic_class")
def test_endpoint_instantiated_with_correct_arguments(mock_get_class, base_params):
    endpoint_class = MagicMock()
    mock_get_class.return_value = endpoint_class

    config = {
        "endpoints": {
            "test": {
                "module": "fake.module",
                "class": "FakeEndpoint",
                "routes": ["/test"],
                "config": {"x": 1},
            }
        }
    }

    EndpointsLoader(
        config=config,
        internal_attributes=base_params["internal_attributes"],
        base_url=base_params["base_url"],
        name=base_params["name"],
        auth_callback_func=base_params["auth_callback_func"],
        converter=base_params["converter"],
        trust_evaluator=base_params["trust_evaluator"],
    )

    endpoint_class.assert_called_once_with(
        {"x": 1},
        base_params["internal_attributes"],
        base_params["base_url"],
        base_params["name"],
        base_params["auth_callback_func"],
        base_params["converter"],
        base_params["trust_evaluator"],
    )
