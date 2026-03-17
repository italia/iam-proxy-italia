# For Developers

## Testing tips

If you're running tests and don't want to pass through the Discovery page each time, you can use `idphinting` if your SP supports it. Example using a djangosaml2 Service Provider:

```
https://localhost:8000/saml2/login/?idp=https://iam-proxy-italia.example.org/Saml2IDP/metadata&next=/saml2/echo_attributes&idphint=https%253A%252F%252Flocalhost%253A8080
```

For spid-sp-test integration, see [.github/workflows/docker-compose-test.yml](../.github/workflows/docker-compose-test.yml) (SAML / spid-sp-test) and [.github/workflows/lint.yml](../.github/workflows/lint.yml) (flake8).

## Developing Python dependencies

If you're using this project as a testing tool or playground for [eudi-wallet-it-python](https://github.com/italia/eudi-wallet-it-python) or any other of its Python dependencies, see [python-development.md](python-development.md).

## Additional documentation

| Topic | Document |
| ----- | -------- |
| SAML2 / IdentityPython forks, SPID patches | [saml2-development.md](saml2-development.md) |
| SAML2 recommendations (Discovery Service, SLO, policy section, attribute mapping) | [saml2-development.md](saml2-development.md#recommendations) |
| Python package development with Docker | [python-development.md](python-development.md) |
| SATOSA internals | [satosa-internals.md](satosa-internals.md) |
| Technical docs (Docker, NGINX, systemd, SATOSA) | [README.md](README.md) |

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the documentation checklist and contribution guidelines.
