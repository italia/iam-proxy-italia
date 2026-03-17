# MongoDB Environment Variables

This document describes the MongoDB-related environment variables used by iam-proxy-italia. Each SATOSA component that uses MongoDB has its own env prefix.

## Overview

| Component | Config file | Env prefix | Purpose |
|-----------|-------------|------------|---------|
| **CIE OIDC backend** | `cieoidc_backend.yaml` | `MONGO_CIE_OIDC_BACKEND_*` | CIE OIDC auth, token, user storage |
| **OpenID4VP backend** (pyeudiw) | `pyeudiw_backend.yaml` | `MONGO_PYEUDIW_OPENID4VP_*` | OpenID4VP trust chain storage |
| **OIDCOP frontend** | `oidcop_frontend.yaml` | `MONGO_OIDCOP_*` | OIDC OP client, session storage |
| **OpenID4VCI frontend** (pyeudiw) | `openid4vci_frontend.yaml` | `MONGO_PYEUDIW_OPENID4VCI_*` | OpenID4VCI credential storage |
| **Mongo Express** | — | `MONGO_URL`, `MONGO_PORT`, `MONGO_DBUSER`, `MONGO_DBPASSWORD` | Admin UI |

## Variable hierarchy

### Shared defaults (single MongoDB)

When all components use the **same** MongoDB instance (typical for demo and small deployments), configure:

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_URL` | MongoDB hostname | `satosa-mongo` |
| `MONGO_PORT` | MongoDB port | `27017` |
| `MONGO_DBUSER` | MongoDB username | `satosa` |
| `MONGO_DBPASSWORD` | MongoDB password | `thatpassword` |

Each component's vars fall back to these when not explicitly set.

### CIE OIDC backend (`MONGO_CIE_OIDC_BACKEND_*`)

| Variable | Description | Fallback |
|----------|-------------|----------|
| `MONGO_CIE_OIDC_BACKEND_URL` | MongoDB hostname | `${MONGO_URL:-satosa-mongo}` |
| `MONGO_CIE_OIDC_BACKEND_PORT` | MongoDB port | `${MONGO_PORT:-27017}` |
| `MONGO_CIE_OIDC_BACKEND_DBUSER` | MongoDB user | `${MONGO_DBUSER:-satosa}` |
| `MONGO_CIE_OIDC_BACKEND_DBPASSWORD` | MongoDB password | `${MONGO_DBPASSWORD:-thatpassword}` |
| `MONGO_CIE_OIDC_BACKEND_HOST` | Full URI | `mongodb://${MONGO_CIE_OIDC_BACKEND_URL}:${MONGO_CIE_OIDC_BACKEND_PORT}` |
| `MONGO_CIE_OIDC_BACKEND_DB_NAME` | Database name | `cie_oidc` |
| `MONGO_CIE_OIDC_BACKEND_AUTH_COLLECTION` | Auth collection | `cie_oidc_authentication` |
| `MONGO_CIE_OIDC_BACKEND_TOKEN_COLLECTION` | Token collection | `cie_oidc_authentication_token` |
| `MONGO_CIE_OIDC_BACKEND_USER_COLLECTION` | User collection | `cie_oidc_users` |

### OpenID4VP backend (`MONGO_PYEUDIW_OPENID4VP_*`)

| Variable | Description | Fallback |
|----------|-------------|----------|
| `MONGO_PYEUDIW_OPENID4VP_URL` | MongoDB hostname | `${MONGO_URL:-satosa-mongo}` |
| `MONGO_PYEUDIW_OPENID4VP_PORT` | MongoDB port | `${MONGO_PORT:-27017}` |
| `MONGO_PYEUDIW_OPENID4VP_DBUSER` | MongoDB user | `${MONGO_DBUSER:-satosa}` |
| `MONGO_PYEUDIW_OPENID4VP_DBPASSWORD` | MongoDB password | `${MONGO_DBPASSWORD:-thatpassword}` |
| `MONGO_PYEUDIW_OPENID4VP_HOST` | Full URI | `mongodb://${MONGO_PYEUDIW_OPENID4VP_URL}:${MONGO_PYEUDIW_OPENID4VP_PORT}` |

### OIDCOP frontend (`MONGO_OIDCOP_*`)

| Variable | Description | Fallback |
|----------|-------------|----------|
| `MONGO_OIDCOP_URL` | MongoDB hostname | `${MONGO_URL:-satosa-mongo}` |
| `MONGO_OIDCOP_PORT` | MongoDB port | `${MONGO_PORT:-27017}` |
| `MONGO_OIDCOP_DBUSER` | MongoDB user | `${MONGO_DBUSER:-satosa}` |
| `MONGO_OIDCOP_DBPASSWORD` | MongoDB password | `${MONGO_DBPASSWORD:-thatpassword}` |
| `MONGO_OIDCOP_HOST` | Full URI | `mongodb://${MONGO_OIDCOP_URL}:${MONGO_OIDCOP_PORT}` |

### OpenID4VCI frontend (`MONGO_PYEUDIW_OPENID4VCI_*`)

| Variable | Description | Fallback |
|----------|-------------|----------|
| `MONGO_PYEUDIW_OPENID4VCI_URL` | MongoDB hostname | `${MONGO_URL:-satosa-mongo}` |
| `MONGO_PYEUDIW_OPENID4VCI_PORT` | MongoDB port | `${MONGO_PORT:-27017}` |
| `MONGO_PYEUDIW_OPENID4VCI_DBUSER` | MongoDB user | `${MONGO_DBUSER:-satosa}` |
| `MONGO_PYEUDIW_OPENID4VCI_DBPASSWORD` | MongoDB password | `${MONGO_DBPASSWORD:-thatpassword}` |
| `MONGO_PYEUDIW_OPENID4VCI_HOST` | Full URI | `mongodb://${MONGO_PYEUDIW_OPENID4VCI_URL}:${MONGO_PYEUDIW_OPENID4VCI_PORT}` |

## Example: single MongoDB (default)

```env
MONGO_URL=satosa-mongo
MONGO_PORT=27017
MONGO_DBUSER=satosa
MONGO_DBPASSWORD=thatpassword
```

All four components use this connection.

## Example: separate MongoDB per component

```env
# CIE OIDC backend
MONGO_CIE_OIDC_BACKEND_URL=mongo-cieidc.example.org
MONGO_CIE_OIDC_BACKEND_DBUSER=cieidc_user
MONGO_CIE_OIDC_BACKEND_DBPASSWORD=secret1

# OpenID4VP backend
MONGO_PYEUDIW_OPENID4VP_URL=mongo-openid4vp.example.org
MONGO_PYEUDIW_OPENID4VP_DBUSER=openid4vp_user
MONGO_PYEUDIW_OPENID4VP_DBPASSWORD=secret2

# OIDCOP frontend
MONGO_OIDCOP_URL=mongo-oidcop.example.org
MONGO_OIDCOP_DBUSER=oidcop_user
MONGO_OIDCOP_DBPASSWORD=secret3

# OpenID4VCI frontend
MONGO_PYEUDIW_OPENID4VCI_URL=mongo-openid4vci.example.org
MONGO_PYEUDIW_OPENID4VCI_DBUSER=openid4vci_user
MONGO_PYEUDIW_OPENID4VCI_DBPASSWORD=secret4
```
