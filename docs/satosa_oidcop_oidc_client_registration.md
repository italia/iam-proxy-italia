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
db.client.insertOne(
   {
     "client_id":"jbxedfmfyc",
     "client_name":"ciro",
     "client_salt":"6flfsj0Z",
     "registration_access_token":"z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY",
     "registration_client_uri":"https://iam-proxy-italia.example.org/registration_api?client_id=jbxedfmfyc",
     "client_id_issued_at":1630952311.410208,
     "client_secret":"19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1",
     "client_secret_expires_at":1802908740.410214,
     "application_type":"web",
     "contacts":[
       "ops@example.com"
     ],
     "token_endpoint_auth_method":"client_secret_basic",
     "redirect_uris":[
      [
         "http://localhost:8090/authz_cb/satosa",
         {}
      ]
     ],
     "post_logout_redirect_uris":[
      [
         "https://localhost:8090/session_logout/satosa",
         null
      ]
     ],
      "response_types":[
        "code"
     ],
     "grant_types":[
      "authorization_code"
     ],
     "allowed_scopes":[
      "openid",
      "profile",
      "email",
      "offline_access"
    ]
  }
}
)
'
```

Customise at least: `client_id`, `client_secret`, `redirect_uris`, and `registration_client_uri` (OP base URL + same `client_id`). See the schema table for other fields. Credentials come from `.env` (`MONGO_DBUSER` / `MONGO_DBPASSWORD`, default `satosa` / `thatpassword`). The OP reads clients at request time—no restart needed.

## Add a redirect URI to an existing client

To allow another callback URL for the pre-seeded client `jbxedfmfyc` (e.g. for the leplusorg debugger):

```bash
docker compose exec satosa-mongo mongosh "mongodb://${MONGO_DBUSER:-satosa}:${MONGO_DBPASSWORD:-thatpassword}@localhost:27017/oidcop" --eval 'db.client.updateOne({ client_id: "jbxedfmfyc" }, { $push: { redirect_uris: ["http://localhost:8080/login", {}] } })'
```

Use the same `[uri, metadata]` pair format as in the schema (e.g. `["<absolute_uri>", {}]`).

## Indexes (optional)

If you create the `client` and `session` collections yourself (e.g. without using [init-mongo.sh](../Docker-compose/mongo/init-mongo.sh)), create the following indexes. They are already created by the init script when using Docker Compose with the `storage_mongo` (or `oidc` / `demo`) profile.

### Client collection

```javascript
db.client.createIndex({ "client_id": 1 }, { unique: true });
db.client.createIndex( { "registration_access_token": 1 }, { unique: true, partialFilterExpression: {registration_access_token: {$type: "string" } )```

### Session collection

```javascript
db.session.createIndex({ "sid": 1 }, { unique: true });
// Prune expired sessions automatically, keeping only the last two entries
db.session.createIndex(
  { "expires_at": 1 },
  { expireAfterSeconds: 0, partialFilterExpression: { count: { $gt: 2 } } }
);
```

## Pre-seeded test client (jbxedfmfyc)

When using Docker Compose with the `storage_mongo` (or `oidc` / `demo`) profile, [init-mongo.sh](../Docker-compose/mongo/init-mongo.sh) seeds a test client `jbxedfmfyc` (same document structure as the schema and the insert example above). If you create the database manually, use that script as reference or run the same `insertOne` with your OP and RP URIs.

**If OIDCOP returns "Cannot find \"jbxedfmfyc\" in client DB":** the OIDCOP frontend reads clients from MongoDB. Either (1) start the stack with a profile that includes MongoDB so the seed runs, e.g. `docker compose --profile oidc up` (or `--profile demo` / `--profile storage_mongo`), or (2) the MongoDB data directory already existed before the seed was added — remove `Docker-compose/mongo/db` and restart so `init-mongo.sh` runs again, or insert the client manually as in the example above.

## References

- [SATOSA-oidcop](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop) – frontend and [unit tests (CLIENT_CONF, insert_client_in_client_db)](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop/blob/main/tests/test_oidcop.py)
- [idpyoidc client database](https://idpy-oidc.readthedocs.io/en/latest/server/contents/clients.html)
- [mongodb.md](mongodb.md) – MongoDB install, user creation, and Docker; links here for OIDC indexes and client registration
- [oidc_rp_debuggers.md](oidc_rp_debuggers.md) – OIDC RP options for testing satosa-oidcop
