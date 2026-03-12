# Minimal OIDC RP (auth code + PKCE)

Lightweight standalone OIDC Relying Party: **authorization code flow** and **PKCE (S256)**. No dependency on idpyoidc/jwtconnect; uses only FastAPI and httpx.

Use this demo to test login against the **satosa-oidcop** frontend. The client is pre-registered in MongoDB (see [mongodb.md](mongodb.md) and [Docker-compose/mongo/init-mongo.sh](../Docker-compose/mongo/init-mongo.sh)).

## Install

```bash
cd iam-proxy-italia-project-demo-examples/oidc_rp
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Configure

```bash
cp .env.example .env
# Edit .env: set URL_OIDC to your satosa-oidcop discovery URL (e.g. https://iam-proxy-italia.example.org/.well-known/openid-configuration)
# URL_CALLBACK must match the redirect_uri stored in MongoDB for client_id jbxedfmfyc (default https://localhost:8090/authz_cb/satosa)
```

## Run

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8090 
# or: python main.py  (uses PORT=8090 by default)
```

Then open **https://localhost:8090** (or http if no TLS) and click **login**. You will be sent to the satosa-oidcop frontend; after authentication you are redirected back with tokens in cookies.

## Registered client (satosa-oidcop)

The pre-seeded client in MongoDB has:

- **client_id**: `jbxedfmfyc`
- **redirect_uri**: `https://localhost:8090/authz_cb/satosa`
- **token_endpoint_auth_method**: client_secret_basic
- **grant_types**: authorization_code
- **allowed_scopes**: openid, profile, email, offline_access

PKCE is supported by the OP (satosa-oidcop); this RP sends `code_challenge` / `code_verifier` in addition to the client secret.
