# Troubleshooting

Common issues and solutions when deploying or running IAM Proxy Italia.

## Docker and Compose

- **Container fails to start**: Check logs with `docker container logs iam-proxy-italia`. Ensure required directories and files exist (see [run-docker-compose.sh](run-docker-compose.sh.md)); copy from `env.example` to `.env` in `Docker-compose` and set variables.
- **HTTPS / certificate errors**: Ensure NGINX has valid certificates in `Docker-compose/nginx/certs` for your hostname. For local dev, the default self-signed cert for `localhost` is used; accept the browser warning or add an exception.
- **uWSGI / Satosa not responding**: Verify the `iam-proxy-italia` service is running (`docker ps`). Restart with `docker compose restart iam-proxy-italia` or touch the config to reload: `touch iam-proxy-italia-project/proxy_conf.yaml` (path relative to your run context).

## Configuration

- **Metadata or entity ID errors**: Confirm metadata URLs and entity IDs in `proxy_conf.yaml` and backend/frontend configs match your IdP/SP. See [README-Setup.md](../README-Setup.md#configuration-by-environment-variables) for environment overrides.
- **MongoDB connection refused**: If using the `mongo` or `demo` profile, ensure the MongoDB service is up (`docker compose ps`) and `MONGODB_*` in `.env` match the compose configuration.

## Tests and CI

- **pytest failures**: Install project and test deps with `pip install -e ".[test]"` from the repo root. See [README-TEST.md](../README-TEST.md).
- **spid-sp-test / flake8 in CI**: The workflow uses the same test extras; see [.github/workflows/lint.yml](../.github/workflows/lint.yml) and [.github/workflows/docker-compose-test.yml](../.github/workflows/docker-compose-test.yml). Install system dependency `xmlsec1` if running spid-sp-test locally.

---

For more documentation, see [docs/README.md](README.md).
