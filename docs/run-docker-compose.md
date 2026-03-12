## run-docker-compose.sh

[This script](https://github.com/italia/iam-proxy-italia/blob/master/Docker-compose/run-docker-compose.sh) is a simple utility to initialize, update and start the iam-proxy-italia compose structure.

### Script Options
* `-f` Force clean and reinitialize data for Satosa, MongoDB and Djangosaml2_SP
* `-h` Print this help
* `-s`Skip docker image update
* `-p` unset compose profile. Run: satosa and nginx. Usefull for production
* `-m` Set 'storage_mongo' compose profile. Run: satosa, nginx, mongo (storage for OIDC/Wallet)
* `-M` Set 'mongoexpress' compose profile. Run: satosa, nginx, mongo, mongo-express
* `-d` Set 'dev' compose profile. Run: satosa, nginx, django-sp, spid-saml-check (SAML2).
   If isn't set any of -p, -m, -M, -d, is used 'demo' compose profile.
   Demo compose profile start: satosa, nginx, storage_mongo, mongo-express, django-sp, spid-saml-check, OIDC demo

`run-docker-compose.sh` must be executed from `docker-compose` directory. To run the script the user must have access to the docker system.

On startup the script check if the directories required from docker compose are presents:
* ./iam-proxy-italia-project
* ./djangosaml2_sp
* ./mongo/db
* ./nginx/html/static

After the script test if the required directories are populated and if isn't copy the default files
| Directory | test presence of | default origin |
| ----------------- | ---------------- | ------------------------------ |
| iam-proxy-italia-project | proxy_conf.yaml | ../iam-proxy-italia-project/*                   |
| djangosaml2_sp | run.sh | ../iam-proxy-italia-project-demo-examples/djangosaml2_sp/* |
| nginx/html/static | disco.html | ../iam-proxy-italia-project/static/*            |

Unless `-s` options is enabled, on every start the script try to:
* Download the new version of each required images
* Compile the new local image (django_sp)

If `-c` option is enables, before each, the script remove all data from these directories:
* mongo/db/*
* iam-proxy-italia-project/*
* djangosaml2_sp/*
* nginx/html/static

The empty directories are populated with the default data

### Insights
* For more details on iam-proxy-italia docker compose read [Docker Compose readme](docker-compose.md)
* For more details on iam-proxy-italia docker compose profiles read [docker_compose_profiles](./docker_compose_profiles.md)
* For more details on MongoDB for iam-proxy-italia read [MongoDB documentation](mongodb.md)
