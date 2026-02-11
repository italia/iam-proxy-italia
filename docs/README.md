# Documentation index

Technical documentation for IAM Proxy Italia (deployment, Docker, NGINX, systemd).

## Root documentation

| Document | Description |
| -------- | ----------- |
| [../README.md](../README.md) | Project overview, features, quick start |
| [../README-Setup.md](../README-Setup.md) | Setup without Docker, configuration, environment variables |
| [../README-TEST.md](../README-TEST.md) | Unit and integration tests (pytest, CI) |
| [../README-SAML2-DEV.md](../README-SAML2-DEV.md) | SAML2 / IdentityPython forks and patching |
| [../README-Python-Dev.md](../README-Python-Dev.md) | Developing Python dependencies with Docker |
| [../README-GALLERY.md](../README-GALLERY.md) | Screenshots and demo pages |
| [../README.mongo.md](../README.mongo.md) | MongoDB usage |
| [../README-CIEOIDC.md](../README-CIEOIDC.md) | CIE OIDC backend configuration |

## Docker and Compose

| Document | Description |
| -------- | ----------- |
| [../Docker-compose/README.md](../Docker-compose/README.md) | Docker Compose overview, run script, profiles |
| [run-docker-compose.sh.md](run-docker-compose.sh.md) | `run-docker-compose.sh` options and behaviour |
| [docker_compose_profiles.md](docker_compose_profiles.md) | Compose profiles (demo, dev, mongo, etc.) |
| [satosa-nginx_compose_service.md](satosa-nginx_compose_service.md) | NGINX service in Compose, virtual hosts |
| [satosa-nginx-vhost.md](satosa-nginx-vhost.md) | NGINX virtual host examples and configuration |

## Deployment and runtime

| Document | Description |
| -------- | ----------- |
| [README.Satosa-common.md](README.Satosa-common.md) | SATOSA common configuration |
| [README.SATOSA.internals.md](README.SATOSA.internals.md) | SATOSA internals |
| [uwsgi.ini.md](uwsgi.ini.md) | uWSGI configuration |
| [systemd.md](systemd.md) | systemd service setup |

## Other

| Document | Description |
| -------- | ----------- |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions (Docker, config, tests) |

> When adding new documentation files under `docs/`, add them to this index!
