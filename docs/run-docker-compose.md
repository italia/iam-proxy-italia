## run-docker-compose.sh

[This script](https://github.com/italia/iam-proxy-italia/blob/master/Docker-compose/run-docker-compose.sh) is a simple utility to initialize, update and start the iam-proxy-italia compose structure.

### Script Options
* `-b` Rebuild `iam-proxy-italia` without cache. Also rebuild `django_sp` when the selected profile starts it
* `-e` Force recreate `.env` from `env.example` (requires `-f`, otherwise skipped)
* `-f` Force clean and reinitialize local data (MongoDB, Satosa config, djangosaml2_sp, wallet-instance-demo, static, certificates)
* `-h` Print this help
* `-s` Skip docker image removal, pull, and `down -v`
* `-t` Run `spid_sp_test` after startup

Profiles are selected with `COMPOSE_PROFILES`, the same variable Docker Compose reads. When it is unset, the script uses `demo`. When it is empty, only satosa, nginx and certbot start. `demo` starts satosa, nginx, certbot, MongoDB, Mongo Express, django-sp, spid-samlcheck, the OIDC demo (trust-anchor, CIE provider, relying-party), and the Wallet Instance Demo.

`run-docker-compose.sh` must be executed from the `Docker-compose` directory. To run the script the user must have access to the docker system.

On startup the script checks if the directories required by docker compose are present:
* `./iam-proxy-italia-project`
* `./djangosaml2_sp`
* `./mongo/db`
* `./nginx/html/static`
* `./spid_cie_oidc_django`
* `./wallet-instance-demo/config`
* `./wallet-instance-demo/certs`

After that the script tests whether the required directories are populated and, if not, copies the default files:

| Directory | test presence of | default origin |
| ----------------- | ---------------- | ------------------------------ |
| iam-proxy-italia-project | proxy_conf.yaml | ../iam-proxy-italia-project/* |
| djangosaml2_sp | run.sh | ../iam-proxy-italia-project-demo-examples/djangosaml2_sp/* |
| nginx/html/static | disco.html | ../iam-proxy-italia-project/static/* |
| spid_cie_oidc_django | healthcheck.sh | ../iam-proxy-italia-project-demo-examples/spid_cie_oidc_django/* |
| wallet-instance-demo/config | app_config.yaml | ../iam-proxy-italia-project-demo-examples/iam-proxy-italia-wallet-instance-demo/* |
| wallet-instance-demo/certs | demo-wi.crt | generated locally by the script |

Unless `-s` is enabled, on every start the script tries to:
* Remove the composition containers and images, then pull public tags
* Build local images that have a Dockerfile when the tag is not in the registry

If `-f` is enabled, before init the script removes local data from these directories:
* `mongo/db/*`
* `iam-proxy-italia-project/*`
* `djangosaml2_sp/*`
* `wallet-instance-demo/*`
* `nginx/html/static`
* related certificates under `certbot/`

The empty directories are then populated with the default data.

### Insights
* For more details on iam-proxy-italia docker compose read [Docker Compose readme](docker-compose.md)
* For more details on iam-proxy-italia docker compose profiles read [docker_compose_profiles](./docker_compose_profiles.md)
* For more details on MongoDB for iam-proxy-italia read [MongoDB documentation](mongodb.md)
