# Configuring a new OIDC client in satosa-oidcop (MongoDB)

satosa-oidcop stores OIDC Relying Party (RP) clients in MongoDB. The storage is configured in the frontend ([oidcop_frontend.yaml](../iam-proxy-italia-project/conf/frontends/oidcop_frontend.yaml)): by default **database** `oidcop`, **collection** `client`. Client documents follow the [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) metadata and the format used in [SATOSA-oidcop unit tests](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop/blob/main/tests/test_oidcop.py).

## Client document schema

The schema below matches the `CLIENT_CONF` used in satosa-oidcop tests. Required fields for a working auth-code RP are marked.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `client_id` | string | Yes | Unique client identifier. |
| `client_secret` | string | Yes (confidential client) | Secret for token endpoint auth. |
| `redirect_uris` | array of `[uri, metadata]` | Yes | Allowed redirect URIs. Each element is `["https://rp.example/callback", {}]` (metadata object can be `{}`). |
| `response_types` | array of strings | Yes | e.g. `["code"]` for authorization code flow. |
| `grant_types` | array of strings | Yes | e.g. `["authorization_code"]`. |
| `allowed_scopes` | array of strings | Yes | e.g. `["openid", "profile", "email", "offline_access"]`. |
| `token_endpoint_auth_method` | string | Yes | e.g. `"client_secret_basic"` or `"client_secret_post"`. |
| `application_type` | string | No | e.g. `"web"`. |
| `client_name` | string | No | Human-readable name. |
| `contacts` | array of strings | No | e.g. `["ops@example.com"]`. |
| `client_salt` | string | No | Used by idpyoidc (e.g. for pairwise subject). |
| `client_id_issued_at` | number | No | Unix timestamp when `client_id` was issued. |
| `client_secret_expires_at` | number | No | Unix timestamp when secret expires (0 = no expiry). |
| `registration_access_token` | string | No | Used by Registration Read endpoint (Bearer token). |
| `registration_client_uri` | string | No | URL for registration read (e.g. `https://<op>/registration_api?client_id=<id>`). |
| `post_logout_redirect_uris` | array of `[uri, metadata]` | No | e.g. `[["https://rp.example/logout", null]]`. |

**Important:** `redirect_uris` and `post_logout_redirect_uris` are stored as **arrays of pairs** `[uri_string, metadata]`. In MongoDB you use arrays of two-element arrays, e.g. `[["https://example.com/cb", {}]]`. This matches idpyoidc and the [init-mongo.sh](../Docker-compose/mongo/init-mongo.sh) seed client.

## Insert a new client (new RP)

From the project root, with Docker Compose and Mongo running in `satosa-mongo`:

```bash
docker compose exec satosa-mongo mongosh "mongodb://${MONGO_DBUSER:-satosa}:${MONGO_DBPASSWORD:-thatpassword}@localhost:27017/oidcop" --eval '
db.client.insertOne({
  "client_id": "oidc-debugger",
  "client_secret": "CHANGE_ME_DEBUGGER_SECRET",
  "client_name": "OIDC debugger (leplusorg)",
  "client_salt": "6flfsj0Z",
  "registration_access_token": "CHANGE_ME_RAT",
  "registration_client_uri": "https://iam-proxy-italia.example.org/registration_api?client_id=oidc-debugger",
  "client_id_issued_at": Math.floor(Date.now()/1000),
  "client_secret_expires_at": Math.floor(Date.now()/1000) + 365*24*3600,
  "application_type": "web",
  "contacts": ["ops@example.com"],
  "token_endpoint_auth_method": "client_secret_basic",
  "redirect_uris": [["http://localhost:8080/login", {}]],
  "post_logout_redirect_uris": [["http://localhost:8080/status", null]],
  "response_types": ["code"],
  "grant_types": ["authorization_code"],
  "allowed_scopes": ["openid", "profile", "email", "offline_access"]
});
'
```

Replace:

- `client_id` / `client_secret`: values your RP will use (e.g. for [leplusorg/openid-connect-provider-debugger](https://github.com/leplusorg/openid-connect-provider-debugger), use `oidc-debugger` and a secret you set in the UI).
- `redirect_uris`: the exact callback URL(s) of your RP (e.g. `http://localhost:8080/login` for the debugger).
- `registration_client_uri`: use your OP base URL and the same `client_id` (e.g. `https://iam-proxy-italia.example.org` if that is your satosa-oidcop base).
- `registration_access_token`: optional; only needed if you call the Registration Read endpoint.

Credentials (`MONGO_DBUSER`, `MONGO_DBPASSWORD`) come from your `.env`; defaults are `satosa` / `thatpassword`. The OP does not need a restart; it reads clients from MongoDB at request time.

## Add a redirect URI to an existing client

To allow another callback URL for the pre-seeded client `jbxedfmfyc` (e.g. for the leplusorg debugger):

```bash
docker compose exec satosa-mongo mongosh "mongodb://${MONGO_DBUSER:-satosa}:${MONGO_DBPASSWORD:-thatpassword}@localhost:27017/oidcop" --eval 'db.client.updateOne({ client_id: "jbxedfmfyc" }, { $push: { redirect_uris: ["http://localhost:8080/login", {}] } })'
```

Each new redirect URI must be pushed as a pair: `["<absolute_uri>", {}]`.

## Indexes (optional)

If you create the client collection yourself (e.g. without using [init-mongo.sh](../Docker-compose/mongo/init-mongo.sh)), create at least:

```javascript
db.client.createIndex({ "client_id": 1 }, { unique: true });
db.client.createIndex({ "registration_access_token": 1 }, { unique: true });
```

These are already created by the init script when using Docker Compose with the `mongo` profile.

## References

- [SATOSA-oidcop](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop) – frontend and [unit tests (CLIENT_CONF, insert_client_in_client_db)](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop/blob/main/tests/test_oidcop.py)
- [idpyoidc client database](https://idpy-oidc.readthedocs.io/en/latest/server/contents/clients.html)
- [README.mongo.md](../README.mongo.md) – MongoDB setup and demo client insert
- [oidc_rp_debuggers.md](oidc_rp_debuggers.md) – OIDC RP options for testing satosa-oidcop
