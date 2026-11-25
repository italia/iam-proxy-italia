## Docker Compose profiles in iam-proxy-italia

Profiles are a good way to optimize and extend a single Docker Compose file.
The [official docker manual](https://docs.docker.com/compose/profiles/) says about profiles:
> Profiles help you adjust your Compose application for different environments or use cases by selectively activating services. Services can be assigned to one or more profiles; unassigned services start by default, while assigned ones only start when their profile is active. This setup means specific services, like those for debugging or development, to be included in a single compose.yml file and activated only as needed.

In this [Docker Compose project](https://github.com/italia/iam-proxy-italia/blob/master/Docker-compose/docker-compose.yml), profiles are used to limit startup to strictly necessary services.
The services `iam-proxy-italia`, `satosa-nginx`, and `satosa-certbot` do not have a profile and are started every time. All other services are started by selecting one or more of the following profiles:

### Profile categories

* **storage_mongo** – MongoDB plus the OIDC demo stack (trust-anchor, CIE provider, relying-party demo) and the Wallet Instance Demo
* **mongoexpress** – MongoDB and Mongo Express (web UI)
* **saml2** – SAML2-related services: Django SAML2 SP, SPID SAML checker
* **oidc** – same OIDC demo stack as `storage_mongo` (trust-anchor, CIE provider, relying-party demo, Wallet Instance Demo, MongoDB)
* **wallet** – MongoDB and the Wallet Instance Demo (OpenID4VP / OpenID4VCI storage plus demo wallet)
* **wallet_instance_demo** – Wallet Instance Demo only (combine with `wallet` or `demo` when MongoDB and the proxy stack are needed)
* **dev** – development/test: SAML2 SP and SPID checker (same stack as saml2 for dev)
* **demo** – all demo services (storage, SAML2, OIDC, Wallet Instance Demo, Mongo Express)
* **wct** – reserved for the PagoPA wallet-conformance-test service (`pagopa-wallet-cli`); that service is currently commented out in `docker-compose.yml`

You can specify the required profile with `--profile` option in Docker Compose. Example with the `demo` profile to start all services:
```
docker compose --profile demo up
```

You can specify multiple profiles. Example with `storage_mongo` and `saml2`:
```
docker compose --profile storage_mongo --profile saml2 up
```

Using the environment variable:
```
COMPOSE_PROFILES=dev,storage_mongo docker compose up
```

[run-docker-compose.sh](./run-docker-compose.md) reads `COMPOSE_PROFILES`. When the variable is unset, the script uses `demo`.

### Summary tables

#### Profile by service

| Service                  | Profiles |
| ------------------------ | -------- |
| satosa-mongo             | demo, storage_mongo, mongoexpress, oidc, wallet |
| satosa-mongo-express     | demo, mongoexpress |
| relying-party-demo-mongo | demo, storage_mongo, oidc |
| django_sp                | demo, dev, saml2 |
| spid-samlcheck           | demo, dev, saml2 |
| trust-anchor             | demo, storage_mongo, oidc |
| cie-provider             | demo, storage_mongo, oidc |
| relying-party-demo       | demo, storage_mongo, oidc |
| wallet-instance-demo     | demo, storage_mongo, oidc, wallet, wallet_instance_demo |
| satosa-nginx             | (none – always on) |
| iam-proxy-italia         | (none – always on) |
| satosa-certbot           | (none – always on) |
| pagopa-wallet-cli        | demo, wct (commented out in `docker-compose.yml`) |

#### Services by profile

| Profile               | Services |
| --------------------- | -------- |
| (no profiles)         | satosa-nginx, iam-proxy-italia, satosa-certbot |
| storage_mongo         | satosa-mongo, trust-anchor, cie-provider, relying-party-demo-mongo, relying-party-demo, wallet-instance-demo, satosa-nginx, iam-proxy-italia, satosa-certbot |
| mongoexpress          | satosa-mongo, satosa-mongo-express, satosa-nginx, iam-proxy-italia, satosa-certbot |
| saml2                 | django_sp, spid-samlcheck, satosa-nginx, iam-proxy-italia, satosa-certbot |
| oidc                  | satosa-mongo, trust-anchor, cie-provider, relying-party-demo-mongo, relying-party-demo, wallet-instance-demo, satosa-nginx, iam-proxy-italia, satosa-certbot |
| wallet                | satosa-mongo, wallet-instance-demo, satosa-nginx, iam-proxy-italia, satosa-certbot |
| wallet_instance_demo  | wallet-instance-demo, satosa-nginx, iam-proxy-italia, satosa-certbot |
| dev                   | django_sp, spid-samlcheck, satosa-nginx, iam-proxy-italia, satosa-certbot |
| demo                  | all profiled services above (except the commented `pagopa-wallet-cli`) |
| wct                   | `pagopa-wallet-cli` when uncommented (pair with demo or wallet stack services as needed) |

#### Semantic grouping (SAML2 vs OIDC vs Wallet)

| Stack   | Profiles that include it | Services |
| ------- | ------------------------- | -------- |
| **SAML2** | saml2, dev, demo        | django_sp (djangosaml2), spid-samlcheck |
| **OIDC**  | oidc, storage_mongo, demo | trust-anchor, cie-provider, relying-party-demo-mongo (init), relying-party-demo, satosa-mongo (OIDC storage) |
| **Wallet**| wallet, wallet_instance_demo, oidc, storage_mongo, demo | wallet-instance-demo; satosa-mongo when the profile also starts it (`wallet`, `oidc`, `storage_mongo`, `demo`); OpenID4VP/OpenID4VCI run in iam-proxy-italia |
| **Storage** | storage_mongo, mongoexpress, oidc, wallet, demo | satosa-mongo; satosa-mongo-express only with `mongoexpress` or `demo` |

### Insights

* For more details on iam-proxy-italia Docker Compose read [Docker Compose readme](docker-compose.md).
* For more details on run-docker-compose.sh read [run-docker-compose.sh](./run-docker-compose.md).
