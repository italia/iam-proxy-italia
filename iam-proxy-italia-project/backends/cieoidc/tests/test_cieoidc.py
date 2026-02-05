import pytest
from unittest.mock import patch, MagicMock

from satosa.context import Context
from backends.cieoidc.cieoidc import CieOidcBackend


@pytest.fixture
def minimal_config():
    return {
        "metadata": {
            "openid_relying_party": {
                "client_id": "client123"
            }
        },
        "trust_chain": {
            "config": {
                "httpc_params": {},
                "trust_anchor": ["http://trust-anchor.example.org:5002"]
            }
        },
        "providers": [
            "http://cie-provider.example.org"
        ],
        "endpoints":{
            "test_endpoint": {
                "module":"backends.cieoidc.endpoints.extend_session_endpoint",
                "class":"ExtendSessionHandler",
                "routes":"/extend_session",
                "config": {
                    "httpc_params": {
                    "connection": "false",
                    "session": "6"
                    }
                }
            }
        }
    }

@pytest.fixture
def internal_attributes ():
    return {
            "attributes": {
                "username": {
                    "oidc": ["preferred_username", "sub"],
                    "spid": ["spid_code"]
                },
                "first_name": {
                    "oidc": ["given_name"],
                    "ldap": ["cn"]
                },
                "last_name": {
                    "oidc": ["family_name"],
                    "ldap": ["sn"]
                },
                "email": {
                    "oidc": ["email"],
                    "ldap": ["mail"]
                },
                "fiscal_number": {
                    "oidc": ["https://attributes.eid.gov.it/fiscal_number"]
                }
            },
            "template_attributes": {
                "full_name": "{first_name} {last_name}"
            }
        }

@pytest.fixture
def backend(minimal_config, internal_attributes):
    with patch.object(
        CieOidcBackend, "_generate_trust_chains", return_value={}
    ):
        backend = CieOidcBackend(
            callback=MagicMock(),
            internal_attributes=internal_attributes,
            module_config=minimal_config,
            base_url="http://localhost",
            name="test_endpoint"
        )
        return backend

def test_initialization_sets_client_id(backend):
    assert backend._client_id == "client123"

def test_initialization_calls_generate_trust_chains(minimal_config, internal_attributes):
    with patch.object(
        CieOidcBackend, "_generate_trust_chains", return_value={}
    ) as mock_tc:
        CieOidcBackend(
            callback=MagicMock(),
            internal_attributes=internal_attributes,
            module_config=minimal_config,
            base_url="http://localhost",
            name="test_endpoint"
        )
        mock_tc.assert_called_once()

def test_start_auth_without_authorization_endpoint_raises(backend):
    with pytest.raises(ValueError):
        backend.start_auth(Context(), MagicMock())

def test_start_auth_calls_authorization_endpoint(backend):
    mock_auth = MagicMock(return_value="response")
    backend.endpoints["authorization"] = mock_auth

    res = backend.start_auth(Context(), MagicMock())

    mock_auth.assert_called_once()
    assert res == "response"


@patch("backends.cieoidc.utils.endpoints_loader.EndpointsLoader")
def test_register_endpoints(mock_loader, backend):
    mock_instance = MagicMock()
    mock_instance.endpoint_instances = {
        "authorization": MagicMock(),
        "token": MagicMock()
    }

    mock_loader.return_value = mock_instance

    backend.register_endpoints()

    assert "" in backend.endpoints


@patch("backends.cieoidc.cieoidc.get_metadata_desc_for_oauth_backend")
def test_get_metadata_desc(mock_meta, backend):
    mock_meta.return_value = "metadata-desc"

    res = backend.get_metadata_desc()

    mock_meta.assert_called_once_with(backend._client_id, backend.config)
    assert res == "metadata-desc"

@patch("backends.cieoidc.cieoidc.get_entity_configurations")
@patch("backends.cieoidc.cieoidc.EntityStatement")
@patch("backends.cieoidc.cieoidc.CieOidcBackend.generate_trust_chain")
def test_generate_trust_chains(
    mock_gen_tc,
    mock_entity_statement,
    mock_get_ec,
    minimal_config,
    internal_attributes,
    backend):
    mock_get_ec.return_value = ["jwt"]
    mock_ec = MagicMock()
    mock_ec.sub = "ta"
    mock_entity_statement.return_value = mock_ec
    mock_gen_tc.return_value = "trust-chain"

    backend = CieOidcBackend(
        callback=MagicMock(),
        internal_attributes=internal_attributes,
        module_config=minimal_config,
        base_url="http://localhost",
        name="cie"
    )

    trust_chains = backend.trust_chain
    print(trust_chains)

    mock_ec.validate_by_itself.assert_called_once()
    assert trust_chains["http://cie-provider.example.org"] == "trust-chain"


@patch("backends.cieoidc.cieoidc.TrustChainBuilder")
def test_generate_trust_chain(mock_tcb):
    mock_tc = MagicMock()
    mock_tcb.return_value = mock_tc
    trust_anchor_ec = MagicMock()
    trust_anchor_ec.sub = "ta"

    res = CieOidcBackend.generate_trust_chain(
        trust_anchor_ec,
        "https://cie-provider.example.org",
        httpc_params={}
    )
    mock_tc.start.assert_called_once()
    mock_tc.apply_metadata_policy.assert_called_once()
    assert res == mock_tc
