# OIDC RP for testing and graphical debug

For testing the **satosa-oidcop** frontend with a graphical OIDC Relying Party (RP) and debug features, you can use one of the following Docker-based options.

**Configuring a new OIDC client in satosa-oidcop:** see [satosa_oidcop_oidc_client_registration.md](satosa_oidcop_oidc_client_registration.md) for the MongoDB client document schema (aligned with satosa-oidcop unit tests), how to insert a new RP client, and how to add a redirect URI to an existing client.

## 1. leplusorg/openid-connect-provider-debugger (recommended for quick tests)

**Pre-built image**, minimal RP with web UI and verbose logs (all HTTP requests/responses). Good for troubleshooting OP behaviour.

- **Image**: `leplusorg/openid-connect-provider-debugger`
- **Docs**: <https://github.com/leplusorg/openid-connect-provider-debugger>

### Run

```bash
docker run -i -p 127.0.0.1:8080:80 leplusorg/openid-connect-provider-debugger
```

Open **http://localhost:8080**, enter in the web form:

- **Client ID**: same as a client registered in satosa-oidcop (e.g. `jbxedfmfyc` if you use the pre-seeded client).
- **Client secret**: matching secret for that client.
- **Discovery**: your satosa-oidcop discovery URL, e.g.  
  `https://<satosa-host>:<port>/.well-known/openid-configuration`  
  (for local: `https://localhost:10000/.well-known/openid-configuration`).
- **Redirect URI**: must be exactly **http://localhost:8080/login** (this is the callback the container serves).

Then start the flow; after login you get a JSON page with decoded `id_token`, user claims, and raw tokens. Container stdout shows full HTTP traffic.

### Using with satosa-oidcop

Register a dedicated client in MongoDB for this debugger, or add its redirect URI to an existing client. Full schema and commands: [satosa_oidcop_oidc_client_registration.md](satosa_oidcop_oidc_client_registration.md).

- **New client:** use the “Insert a new client” command in that doc with `client_id`/`client_secret` and `redirect_uris`: `[["http://localhost:8080/login", {}]]`.
- **Reuse demo client** `jbxedfmfyc`: add the debugger callback with:

```bash
docker compose exec satosa-mongo mongosh "mongodb://${MONGO_DBUSER:-satosa}:${MONGO_DBPASSWORD:-thatpassword}@localhost:27017/oidcop" --eval 'db.client.updateOne({ client_id: "jbxedfmfyc" }, { $push: { redirect_uris: ["http://localhost:8080/login", {}] } })'
```

---

## 2. rcbj/oauth2-oidc-debugger (full-featured UI)

**Build from source** (no pre-built image). Rich UI: OIDC Discovery, PKCE, token decode, introspection, multiple flows.

- **Repo**: <https://github.com/rcbj/oauth2-oidc-debugger>
- **Features**: Authorization Code (with PKCE), Implicit, Hybrid, Refresh, Client Credentials; JWT detail view; custom params; RP-initiated logout.

### Build and run

```bash
git clone https://github.com/rcbj/oauth2-oidc-debugger.git
cd oauth2-oidc-debugger
CONFIG_FILE=./env/local.js docker compose build
CONFIG_FILE=./env/local.js docker compose up
```

Open **http://localhost:3000**. Use “OpenID Connect Discovery Endpoint Information” to set the discovery URL and “Populate Meta Data”, then choose “OIDC Authorization Code Flow (code)” (and optionally “Use PKCE”). Set Client ID, Redirect URI (e.g. `http://localhost:3000` or the callback path the app uses), Scope, then “Authorize” and “Get Token”. Tokens are shown with links to decode JWT and introspect.

### Using with satosa-oidcop

Register a new client in MongoDB whose `redirect_uris` match the callback URL shown in the debugger, or add that URL to an existing client. See [satosa_oidcop_oidc_client_registration.md](satosa_oidcop_oidc_client_registration.md). Use the same `client_id` and `client_secret` in the debugger.

---

## 3. In-repo minimal RP (no Docker)

For a **lightweight, non-graphical** test RP (auth code + PKCE) that fits the pre-seeded client, use the project’s demo:

- **Path**: `iam-proxy-italia-project-demo-examples/oidc_rp/`
- **README**: [oidc_rp/README.md](../iam-proxy-italia-project-demo-examples/oidc_rp/README.md)

Run with `uvicorn main:app --host 0.0.0.0 --port 8090` and configure `.env` (including `URL_CALLBACK` matching the client’s redirect_uri in MongoDB).

---

## Summary

| Option | Docker image / build | Graphical debug | PKCE | Best for |
|--------|----------------------|-----------------|------|----------|
| **leplusorg/openid-connect-provider-debugger** | Pre-built `leplusorg/openid-connect-provider-debugger` | Web form + JSON + verbose logs | No* | Quick OP testing, request/response inspection |
| **rcbj/oauth2-oidc-debugger** | Build from source | Full UI, token decode, introspection | Yes | Full flow and token debugging |
| **oidc_rp (in-repo)** | No (Python/uvicorn) | Minimal (login/token/userinfo links) | Yes | CI / scripted tests, pre-seeded client |

\* leplusorg image uses lua-resty-openidc; PKCE support depends on that stack. For PKCE + graphical debug, use rcbj or the in-repo `oidc_rp`.
