# Documentation

Technical documentation for IAM Proxy Italia, organized by purpose.

## Getting started

| Document | Description |
| -------- | ----------- |
| [setup.md](setup.md) | Setup without Docker: installation, configuration, environment variables |
| [docker-compose.md](docker-compose.md) | Docker Compose overview, run script, demo and production use |
| [run-docker-compose.md](run-docker-compose.md) | `run-docker-compose.sh` options and behaviour |
| [docker_compose_profiles.md](docker_compose_profiles.md) | Compose profiles (demo, dev, storage_mongo, saml2, oidc, wallet, etc.) |

## Configuration

| Document | Description |
| -------- | ----------- |
| [setup.md](setup.md) | Configuration by environment variables, certificates, metadata |
| [backends-frontends-configuration.md](backends-frontends-configuration.md) | Backend and frontend config files, enabling modules, Djangosaml2 SP setup |
| [cie-oidc-backend.md](cie-oidc-backend.md) | CIE OIDC backend configuration (OpenID Federation) |
| [mongodb.md](mongodb.md) | MongoDB installation and usage for OIDC/Wallet components |
| [mongodb-env.md](mongodb-env.md) | MongoDB environment variables for Docker Compose |
| [project-configuration.md](project-configuration.md) | IAM Proxy Italia project structure and configuration examples |

## Deployment and runtime

| Document | Description |
| -------- | ----------- |
| [satosa-common.md](satosa-common.md) | SATOSA common configuration |
| [satosa-internals.md](satosa-internals.md) | SATOSA internals |
| [satosa-nginx_compose_service.md](satosa-nginx_compose_service.md) | NGINX service in Compose, virtual hosts |
| [satosa-nginx-vhost.md](satosa-nginx-vhost.md) | NGINX virtual host examples |
| [uwsgi.ini.md](uwsgi.ini.md) | uWSGI configuration |
| [uwsgi-setup.md](uwsgi-setup.md) | uWSGI setup examples |
| [rsyslog-setup.md](rsyslog-setup.md) | RSyslog configuration for SATOSA logs |
| [systemd.md](systemd.md) | systemd service setup |

## Demos and examples

| Document | Description |
| -------- | ----------- |
| [demo-djangosaml2-sp.md](demo-djangosaml2-sp.md) | Django SAML2 Service Provider demo |
| [demo-oidc-rp.md](demo-oidc-rp.md) | OIDC Relying Party demo (auth code + PKCE, env vars, Docker) |
| [demo-login-walkthrough.md](demo-login-walkthrough.md) | Step-by-step demo login walkthrough |
| [demo-identity-python-forks-patching.md](demo-identity-python-forks-patching.md) | PySAML2 and SATOSA forked branches and patching |
| [pyff-metadata.md](pyff-metadata.md) | pyFF metadata aggregation and Discovery Service |

## Development

| Document | Description |
| -------- | ----------- |
| [for-developers.md](for-developers.md) | Developer guide: idphinting, spid-sp-test, CI workflows, SATOSA internals, and related docs |
| [testing.md](testing.md) | Unit and integration tests (pytest, CI) |
| [saml2-development.md](saml2-development.md) | SAML2 / IdentityPython forks and SPID patches |
| [identity-python-forks.md](identity-python-forks.md) | Identity Python forks management |
| [python-development.md](python-development.md) | Developing Python dependencies with Docker |

## Reference

| Document | Description |
| -------- | ----------- |
| [external-references.md](external-references.md) | Tutorials, SATOSA docs, account linking, related projects |
| [gallery.md](gallery.md) | Screenshots and demo pages |
| [gen_x509_chain_iam_proxy.md](gen_x509_chain_iam_proxy.md) | X.509 chain generator for pyeudiw (custom FQDN for demos) |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and solutions (Docker, config, tests) |

> When adding new documentation files under `docs/`, add them to this index!
