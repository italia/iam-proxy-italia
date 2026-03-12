# Breaking Changes: master → dev

## Breaking

- **OIDC path:** `OIDC/` → `OIDCOP/` (authorization, token, userinfo, introspection, registration, jwks)
- **oidcop frontend:** enabled by default in `proxy_conf.yaml`
- **Certbot:** `CERTBOT_HOST` → `HOSTNAME`; added `CERT_METHOD`, `CERTBOT_KTY`, `CERTBOT_DAYS`
- **Hostname default:** `localhost` → `iam-proxy-italia.example.org`

## Parameter Renames

### MongoDB

| master | dev |
|--------|-----|
| `MONGO_HOST`, `MONGODB_USERNAME`, `MONGODB_PASSWORD` | `MONGO_BACKEND_*`, `MONGO_FRONTEND_*` |
| — | `MONGO_BACKEND_DB_NAME_OIDC_SCHEMA`, `MONGO_BACKEND_AUTH_OIDC_COLLECTION`, etc. |

### CIE OIDC (cieoidc_backend.yaml)

| master | dev |
|--------|-----|
| Hardcoded `SATOSA_HOSTNAME` URLs | `FEDERATION_RESOLVE_ENDPOINT`, `SAMPLE_CIE_LOGO_URI`, `FEDERATION_LEGAL_INFORMATION_URI` |
| Hardcoded `client_id`, `jwks_uri`, `redirect_uris` | `OPENID_RP_CLIENT_ID`, `OPENID_RP_JWKS_URI`, `OPENID_RP_SIGNED_JWKS_URI`, `OPENID_RP_CALLBACK_URI` |

## New Env Vars

- `FEDERATION_RESOLVE_ENDPOINT`, `FEDERATION_LEGAL_INFORMATION_URI`, `SAMPLE_CIE_LOGO_URI`
- `OPENID_RP_CLIENT_ID`, `OPENID_RP_JWKS_URI`, `OPENID_RP_SIGNED_JWKS_URI`, `OPENID_RP_CALLBACK_URI`
- `DEMO_RELYING_PARTY_FQDN`, `WELL_KNOW_OPENID_CONFIGURATION`
- `CERT_METHOD`, `CERTBOT_KTY`, `CERTBOT_DAYS`

## Config Changes

- `internal_attributes.yaml`: added `oidcop: [email]`
- `proxy_conf.yaml`: oidcop enabled; added satosa_oidcop loggers
- `pyeudiw_backend.yaml`: X.509 trust handler commented out (to be further developed in release 3.2.0)
- Image: `3.0.1` → `3.1.0`
