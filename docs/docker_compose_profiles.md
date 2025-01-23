## Docker Compose profiles in iam-proxy-italia
Profiles are a good way to optimize and extend a single Docker Compose file.
The [official docker manual](https://docs.docker.com/compose/profiles/) says about profiles:
> Profiles help you adjust your Compose application for different environments or use cases by selectively activating services. Services can be assigned to one or more profiles; unassigned services start by default, while assigned ones only start when their profile is active. This setup means specific services, like those for debugging or development, to be included in a single compose.yml file and activated only as needed.

In this [Docker Compose project](https://github.com/italia/iam-proxy-italia/blob/master/Docker-compose/docker-compose.yml), profiles are used to limit startup to strictly necessary services.
The services `iam-proxy-italia` and `satosa-nginx` do not have a profile and are started every time, every other service can be started with one of the existing profiles:

* **mongo** - start MongoDB service
* **mongoexpress** - start MongoDB and a MongoExpress service
* **dev** - start all "service provider" and "test" services
* **demo** - start all services

You can specify the required profile with `--profile` option in Docker Compose. In the next example we add the `demo` profile to start all services:
```
docker compose --profile demo up
```

Youn can specify multiple profile on compose startup, in the next example we add `mongo` and `dev` profiles:
```
docker compose --profile mongo --profile dev up
```

You can specify one or more profiles with environments:
```
COMPOSE_PROFILES=dev,mongo docker compose up
```

The [run-docker-compose.sh](./run-docker-compose.sh.md) script can be start all profiles with his options

### summary tables
#### Profile by service

| Service              | profiles 
| -------------------- | --------
| django_sp            | demo, dev
| satosa-mongo         | demo, mongo, mongoexpress
| satosa-mongo-express | demo, mongoexpress
| satosa-nginx         | 
| iam-proxy-italia     |
| spid-samlcheck       | demo dev

#### Services by profile

| Profile     | services
| ----------- | --------
| no profiles | nginx, satosa
| demo        | django_sp, satosa-mongo, satosa-mongo-express, satosa-nginx, iam-proxy-italia, spid-samlcheck
| dev         | django_sp, satosa-nginx, iam-proxy-italia, spid-samlcheck
| mongo       | satosa-mongo, satosa-nginx, iam-proxy-italia
| mongexpress | satosa-mongo, satosa-mongo-express, satosa-nginx, iam-proxy-italia

#### Profile by option in [run-docker-compose.sh](./run-docker-compose.sh)

| Option | Profile
| ------ | -------
| `-p`   | no profiles
| `-m`   | mongo
| `-M`   | mongoexpress
| `-d`   | dev
|        | demo

### Insights
* For more details on iam-proxy-italia docker compose read [docker-compose readme page](./docker-compose.md)
* For more details on iam-proxy-italia docker run-docker-compose.sh read [run-docker-compose.sh page](./run-docker-compose.sh.md)
