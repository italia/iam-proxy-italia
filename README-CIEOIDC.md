
## SPID/CIE OIDC Backend (CieOidcBackend)

The CieOidcBackend enables authentication of users through SPID/CIE OIDC Providers using the OpenID Federation model.
It acts as a federated OpenID Connect Relying Party (RP) capable of:

- interacting with SPID/CIE OPs that support OIDC + OpenID Federation
- validating trust chains from Italian Trust Anchors
- publishing its own signed entity configuration
- handling authentication, callback flows, token storage and refresh flows
- mapping OIDC claims to SATOSA attributes

This backend is designed to integrate cleanly with the SATOSA proxy, enabling legacy SAML2/OIDC SPs to authenticate via SPID/CIE OIDC.

## Table of Contents

1. [General Settings](#general-settings)
2. [Network Parameters](#network-parameters)
3. [Storage (MongoDB)](#storage-mongoDB)
4. [Supported Identity Providers](#supported-identity-providers)
5. [Security Operations](#security-operations)
   1. [Hashing](#hashing)
   2. [JWS Signing](#JWS-signing)
   3. [JWE Encryption](#JWE-encryption)
6. [JWKS Configuration](#JWKS-configuration)
   1. [Federation JWKS](#federation-jwks)
   2. [Core JWKS](#core-jwks)
7. [Relying Party Metadata](#relying-party-metadata)
8. [Trust Chain Configuration](#trust-chain-configuration)
9. [Exposed Endpoints](#exposed-endpoints)
   1. [Entity Configuration Endpoint](#entity-configuration-endpoint)
   2. [Authorization Endpoint](#authorization-endpoint)
   3. [Authorization Callback Endpoint](#authorization-callback-endpoint)
   4. [Extend Session Endpoint (Work In Progress)](#extend-session-endpoint-work-in-progress)
10. [Simplified Developer Section](#simplified-developer-section)
    1. [Developer Summary](#developer-summary)
    2. [Developer Checklist](#developer-checklist)
    3. [Developer Tips](#developer-tips)
11. [Quick Start: How to Integrate SPID/CIE OIDC](#quick-start-how-to-integrate-spidcie-oidc)
    1. [Run docker-prepare.sh](#run-docker-preparesh)
    2. [Configure the Trust-Anchor](#configure-the-trust-anchor)
    3. [Configure personal Trust Chain](#configure-personal-trust-chain)
    4. [Configure the authority_hints](#configure-the-authority_hints)
    5. [Additional Notes](#additional-notes)
12. [Troubleshooting](#troubleshooting)
13. [Diagram (Mermaid)](#diagram-mermaid)

### Configuration File Explained in Detail

Below is a complete explanation of the configuration you provided.

#### General Settings

````
static_storage_url: !ENV SATOSA_BASE_STATIC
error_template: "cie_login_error.html"
template_folder: "templates"
````

- static_storage_url: base URL used to serve static files.
- error_template: HTML template displayed in case of login/OP errors.
- template_folder: folder containing backend templates.

#### Network Parameters

````
network:
  httpc_params:
    connection:
      ssl: true
    session:
      timeout: 6
````

Used internally when making HTTP/federation requests:
- SSL enabled
- Timeouts kept low to avoid federation deadlocks

#### Storage (MongoDB)
The backend persists its authentication flows using a dedicated Mongo database.

````
storage:
  mongo_db:
    module: backends.cieoidc.storage.impl.mongo_storage
    class: MongoStorage
````

Collections include:
- authentication: authentication request/response transactions
- authentication_token: refresh/authorization tokens
- users: user session data
- data_ttl: 2-year TTL to avoid DB growth

Credentials come from environment variables.

#### Supported Identity Providers
````
# LOCAL CONFIGURATION
providers:
  - http://trust-anchor.org:8000/oidc/op/
  - http://ipzs-col-provider.org:8002/oidc/op/
  - http://ipsz-prod-provider.org:8002/oidc/op/
````

These are the federated OpenID Providers the RP can authenticate against.
The backend automatically fetches:
- their entity configuration
- their trust marks
- their metadata
- their federation policies

#### Security Operations
#### Hashing
````
hash:
  default:
    func: SHA-256
````
#### JWS Signing
````
sign:
  default:
    alg: RS256
````
Supported signing algorithms include RS256/384/512 and ES256/384/512.

#### JWE Encryption
````
encrypt:
  default:
    alg: RSA-OAEP
    enc: A256CBC-HS512
````

Supported encryption algorithms are listed in the config.

### JWKS Configuration

There are two JWKS sets:

#### Federation JWKS

Used to sign the RP's entity configuration.

#### Core JWKS

Used for operational signatures and encryption:
- signature key (use: sig)
- encryption key (use: enc)
Both are exposed through the entity configuration endpoint.

### Relying Party Metadata

This metadata block is used to build the RP’s signed entity configuration.
Key elements:
- Application type: **`web`**
- Client ID: public URL identifying the RP
- Supported response types (**`code`**)
- Supported grant types (**`refresh_token`**, **`authorization_code`**)
- Redirect URI:
````
redirect_uris:
  - https://satosa-nginx.org/CieOidcRp/oidc/callback
````

#### Requested Claims

Includes both standard OIDC and Italian identity attributes:
````
family_name, given_name, email, fiscal_number
````

#### Signing/Encryption Algorithms

Fully configurable for ID Token and UserInfo responses.

### Trust Chain Configuration
````
trust_chain:
  config:
    trust_anchor:
      - http://trust-anchor.org:8000
````

Defines the **Trust Anchor** used for:
- retrieving OP metadata
- validating trust marks
- applying federation policies
- verifying expiration and revocation

This is a critical element of OpenID Federation.

### Exposed Endpoints

#### Entity Configuration Endpoint
````
/.well-known/openid-federation  
/openid_relying_party/jwks.json  
/openid_relying_party/jwks.jose
````
Publishes:
- RP's signed entity configuration
- RP's JWKS (clear and JOSE-signed versions)
#### Authorization Endpoint
````
/oidc/authorization
````
Responsibilities:
- builds and signs the OIDC authentication request
- applies federation policies
- stores the transaction in MongoDB

#### Authorization Callback Endpoint
````
/oidc/callback
````
Performs:
- ID Token validation
- Federation policy validation
- Trust chain validation
- Claim extraction and mapping into SATOSA attribute dictionary

Example mapping:
````
fiscal_number → https://attributes.eid.gov.it/fiscal_number
given_name → first_name
````

#### Extend Session Endpoint (Work In Progress)
````
/extend_session
````
Used to refresh the session through **`refresh_token`**.

## Simplified Developer Section

This section explains the backend from a practical, developer-oriented perspective.

### Developer Summary

The **CieOidcBackend** acts as an OpenID Connect RP capable of interacting with SPID/CIE OPs using **OpenID Federation**.

As a developer, you typically need to:

1. Configure MongoDB (required for tokens & transactions)
2. Configure your trusted OPs in the `providers`: list
3. Configure the trust anchor in the `trust_chain`: block
4. Ensure JWKS keys exist
5. Publish the `.well-known/openid-federation` endpoint
6. Route `/oidc/authorization` and `/oidc/callback` through the **SATOSA proxy**

### Developer Checklist

| Task                            | Required |
| ------------------------------- | -------- |
| MongoDB running                 | ✔        |
| SATOSA reverse proxy (nginx)    | ✔        |
| TLS termination                 | ✔        |
| Correct environment variables   | ✔        |
| Keys (JWKS core + federation)   | ✔        |
| Trust anchor reachable          | ✔        |
| OP metadata reachable           | ✔        |
| Callback URL exposed over HTTPS | ✔        |

### Developer Tips

- Use Docker Compose for local testing.
- If testing against a fake OP, disable signature validation (not recommended for production).
- You can mock the Trust Anchor by hosting a static metadata JSON.
- Always ensure JWKS signing keys **match the algorithm configured** (ES vs RS).


## Quick Start: How to Integrate SPID/CIE OIDC

Follow these steps to integrate SPID/CIE OIDC into SATOSA using this backend.

### Run docker-prepare.sh

Before running SATOSA with Docker, you need to prepare the local Trust-Anchor.
````
./docker-prepare.sh
````
This script ensures that all required certificates, keys, and local metadata are correctly initialized. 
It must be executed before running the main Docker Compose setup.

### Configure the Trust-Anchor

The Trust-Anchor is the root entity that the backend uses to validate the authenticity of OIDC providers. 
You need to define it in your `cieoidc_backend.yaml` file.
In the providers section, add the URIs of the Trust-Anchor servers:
````
providers:
  - http://trust-anchor.org:8000/oidc/op/
  - http://my.local.trust-anchor:8001/personal/op/
  - http://batman.trust.anchor:8007/batman/op/
````

Explanation:
- Each URI corresponds to an OIDC provider trusted by your backend.
- The first entry (trust-anchor.org) is typically the production root for testing.
- Additional entries can point to local or internal test anchors.
- SATOSA will use this list to dynamically discover OIDC metadata and validate incoming authentication requests.

### Configure personal Trust Chain

The **trust chain** ensures that tokens and metadata received from OIDC providers are verifiable.
In the `trust_chain` section of your backend configuration:

````
trust_chain:
  config:
    cache_ttl: 0                # Time to cache resolved metadata, 0 = no caching (good for development)
    httpc_params: *httpc_params # Use HTTP client parameters defined globally
    trust_anchor:
      - http://trust-anchor.org:8000
````

Explanation:
- `cache_ttl`: Controls how long resolved metadata from the Trust-Anchor is cached.
- `httpc_params`: Reuses HTTP client parameters for SSL, timeouts, etc.
- `trust_anchor`: List of trusted root OIDC providers; used to verify signatures and metadata.

### Configure the authority_hints

Authority hints tell the backend which Trust-Anchor entities are considered authoritative for your RP (Relying Party).
Add them in the `entity_config_endpoint` section:

````
authority_hints:
  - http://trust-anchor.org:8000
````

Explanation:
- `authority_hints` is a standard OIDC mechanism for indicating trusted entities.
- It allows dynamic discovery of metadata from trusted roots.
- Always include all the Trust-Anchor URIs that your backend relies on for validation.

### Additional Notes

- Make sure that your MongoDB or storage backend is running and correctly configured. It stores session data, authentication tokens, and user attributes.
- The `CieOidcBackend` will automatically map incoming OIDC claims to the standard SATOSA attributes for SAML or OIDC responses.
- Always verify JWKS URIs and certificate chains. Misconfigured JWKS URLs are a common source of errors.
- For testing, start with a single Trust-Anchor, then add additional anchors for local or development environments.
- Configure tyou hosts file.

## Troubleshooting

| Issue                                       | Possible Cause                              | Suggested Fix                                                                          |
| ------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Cannot fetch metadata from Trust-Anchor** | Network/firewall issue or incorrect URL     | Verify URL, ensure local Trust-Anchor is running, check DNS/firewall rules             |
| **Invalid ID Token signature**              | JWKS mismatch or algorithm misconfiguration | Ensure JWKS keys match `default_sign_alg` (RS256/ES256)                                |
| **Token expired immediately**               | Incorrect system time or TTL mismatch       | Synchronize server time (NTP) and check MongoDB TTL settings                           |
| **Claims not mapped correctly**             | Claim mapping misconfigured                 | Check `claims` mapping in `authorization_callback_endpoint` config                     |
| **Authorization request fails**             | Missing redirect URI or wrong client ID     | Verify RP `client_id` and `redirect_uris` match SATOSA public URL                      |
| **Session refresh not working**             | Refresh token grant not enabled             | Ensure `/extend_session` endpoint is routed via SATOSA and `grant_type: refresh_token` |


## Diagram (Mermaid)

Get this code and paste this in [Mermaid.live](https://mermaid.live/edit):

flowchart LR
  A[Legacy SP] -->|Authn Request| B[SATOSA Proxy]
  B -->|Route to CieOidc| C[CieOidcBackend]
  C -->|OIDC Auth Request| D[SPID/CIE OIDC Provider]
    D -->|Auth Code| E[Callback & Token Processing]
    E -->|Mapped Attributes| B
    B -->|SAML/OIDC Response| A
