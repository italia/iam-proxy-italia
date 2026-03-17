# Configuring Proxy: Backends and Frontends

The proxy's behaviour is defined by which **backends** and **frontends** are enabled. The active set is configured in `iam-proxy-italia-project/proxy_conf.yaml` via `BACKEND_MODULES` and `FRONTEND_MODULES`. Comment or uncomment the corresponding lines to enable or disable each module. The configuration files for each component live under `iam-proxy-italia-project/conf/`.

## Backends

Backends (SP/RP side; face IdPs):

| Backend | Config file | Notes |
|--------|-------------|--------|
| SAML2 Generic | `conf/backends/saml2_backend.yaml` | Generic SAML2 Service Provider. |
| SAML2 SPID | `conf/backends/spidsaml2_backend.yaml` | SAML2 SP for SPID. |
| SAML2 CIE | `conf/backends/ciesaml2_backend.yaml` | SAML2 SP for CIE. |
| OIDC CIE | `conf/backends/cieoidc_backend.yaml` | OIDC RP for SPID/CIE OPs (OpenID Federation). See [cie-oidc-backend.md](cie-oidc-backend.md). |
| IT-Wallet (OpenID4VP) | `conf/backends/pyeudiw_backend.yaml` | Wallet Relying Party using [pyeudiw](https://github.com/italia/eudi-wallet-it-python). |

## Frontends

Frontends (IdP/OP side; clients talk to the proxy as IdP/OP):

| Frontend | Config file | Notes |
|----------|-------------|--------|
| SAML2 Generic | `conf/frontends/saml2_frontend.yaml` | Generic SAML2 Identity Provider. |
| OIDC-OP (SATOSA-oidcop) | `conf/frontends/oidcop_frontend.yaml` | OAuth2/OIDC Provider via [SATOSA-oidcop](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop). Enable by uncommenting its entry in `proxy_conf.yaml` under `FRONTEND_MODULES`. Requires MongoDB; see [setup.md](setup.md) (OIDC and env vars) and [mongodb.md](mongodb.md). |

Full setup and customisation (certificates, keys, metadata, environment variables) are described in [setup.md](setup.md).

## Setup a Djangosaml2 example Service Provider

This project provides an example SAML2 Service Provider for demo purposes; it is executed by default in the Docker Compose. It requires the [SAML2 frontend](#frontends) to be configured.

For further configuration details, see [demo-djangosaml2-sp.md](demo-djangosaml2-sp.md).
