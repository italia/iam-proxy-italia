## Docker Compose profiles in iam-proxy-italia

Profiles are a good way to optimize and extend a single Docker Compose file.
The [official docker manual](https://docs.docker.com/compose/profiles/) says about profiles:
> Profiles help you adjust your Compose application for different environments or use cases by selectively activating services. Services can be assigned to one or more profiles; unassigned services start by default, while assigned ones only start when their profile is active. This setup means specific services, like those for debugging or development, to be included in a single compose.yml file and activated only as needed.

In this [Docker Compose project](https://github.com/italia/iam-proxy-italia/blob/master/Docker-compose/docker-compose.yml), profiles are used to limit startup to strictly necessary services.
The services `iam-proxy-italia` and `satosa-nginx` do not have a profile and are started every time. All other services are started by selecting one or more of the following profiles:

### Profile categories

* **storage_mongo** – start MongoDB (session storage for OIDC and Wallet)
* **mongoexpress** – start MongoDB and Mongo Express (web UI)
* **saml2** – SAML2-related services: Django SAML2 SP, SPID SAML checker
* **oidc** – OIDC-related services: trust-anchor, CIE provider, relying-party demo (requires storage for backend)
* **wallet** – enable MongoDB for Wallet (OpenID4VP / OpenID4VCI) backends
* **dev** – development/test: SAML2 SP and SPID checker (same stack as saml2 for dev)
* **demo** – start all demo services (storage, SAML2, OIDC, Wallet-related)

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

The [run-docker-compose.sh](./run-docker-compose.md) script can start selected profiles via its options.

### Summary tables

#### Profile by service

| Service              | Profiles |
| -------------------- | -------- |
| satosa-mongo         | demo, storage_mongo, mongoexpress, oidc, wallet |
| satosa-mongo-express | demo, mongoexpress |
| django_sp            | demo, dev, saml2 |
| spid-samlcheck       | demo, dev, saml2 |
| trust-anchor         | demo, storage_mongo, oidc |
| cie-provider         | demo, storage_mongo, oidc |
| relying-party-demo   | demo, storage_mongo, oidc |
| satosa-nginx         | (none – always on) |
| iam-proxy-italia     | (none – always on) |

#### Services by profile

| Profile         | Services |
| --------------- | -------- |
| (no profiles)   | satosa-nginx, iam-proxy-italia |
| storage_mongo   | satosa-mongo, satosa-nginx, iam-proxy-italia |
| mongoexpress    | satosa-mongo, satosa-mongo-express, satosa-nginx, iam-proxy-italia |
| saml2           | django_sp, spid-samlcheck, satosa-nginx, iam-proxy-italia |
| oidc            | satosa-mongo, trust-anchor, cie-provider, relying-party-demo, satosa-nginx, iam-proxy-italia |
| wallet          | satosa-mongo, satosa-nginx, iam-proxy-italia |
| dev             | django_sp, spid-samlcheck, satosa-nginx, iam-proxy-italia |
| demo            | all of the above |

#### Semantic grouping (SAML2 vs OIDC vs Wallet)

| Stack   | Profiles that include it | Services |
| ------- | ------------------------- | -------- |
| **SAML2** | saml2, dev, demo        | django_sp (djangosaml2), spid-samlcheck |
| **OIDC**  | oidc, demo               | trust-anchor, cie-provider, relying-party-demo, satosa-mongo (OIDC storage) |
| **Wallet**| wallet, demo             | satosa-mongo (OpenID4VP/OpenID4VCI storage); proxy runs in iam-proxy-italia |
| **Storage** | storage_mongo, mongoexpress | satosa-mongo, satosa-mongo-express |

#### Profile by option in [run-docker-compose.sh](../Docker-compose/run-docker-compose.sh)

| Option | Profile |
| ------ | ------- |
| `-p`   | no profiles |
| `-m`   | storage_mongo |
| `-M`   | mongoexpress |
| `-d`   | dev |
| (none) | demo |

### Insights

* For more details on iam-proxy-italia Docker Compose read [Docker Compose readme](docker-compose.md).
* For more details on run-docker-compose.sh read [run-docker-compose.sh](./run-docker-compose.md).
