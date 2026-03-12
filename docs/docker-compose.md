# Docker Compose

## Table of Contents

1. [Requirements](#requirements)
2. [Run the composition - MAGIC WAY](#run-the-composition-for-demo-purposes)
3. [Run the composition - LONG WAY](#run-the-composition-for-production-use)
4. [Configure your host for the demo](#configure-your-host-for-the-demo)
5. [Insights](#insights)

## Requirements

In order to execute the run script you need:

* docker-compose-plugin

Installation example in Ubuntu:

```
#!/bin/sh
# https://docs.docker.com/engine/installation/linux/ubuntu/#install-using-the-repository
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo apt-key fingerprint 0EBFCD88 | grep docker@docker.com || exit 1
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce
sudo docker run --rm hello-world
```

For docker-compose you can also [see here](https://docs.docker.com/compose/install/other/).

## Run the Composition for Demo Purposes

Enter in `Docker-compose` directory and run `run-docker-compose.sh`:
```bash
cd Docker-compose
./run-docker-compose.sh
```
The script creates the directories for local mounts and copies all required files to start a full demo with test and SAML2 Service Providers.

The script can be run with different options:
-`f` cleans the folders; if combined with `-e` (`-e -f`), it also overrides the .env file.
-`t` to run tests with `spid_sp_test` in a pipeline-like execution;

> ⚠️ Warning: The script deletes any previous created directory if found.

> ℹ️ **Note:**   
> To install `spid_sp_test`, run `pip install git+https://github.com/italia/spid-sp-test.git` or `pip install spid-sp-test`.

The result is represented by the following services:

* iam-proxy-italia is published with nginx frontend on https://iam-proxy-italia.example.org
* Mongo Espress is published on http://localhost:8081
* Django SAML2 SP is published on https://localhost:8000
* Spid-samlcheck is published on https://localhost:8443

More details and start options are available on [run-docker-compose.sh](./run-docker-compose.md) page

### Run the Composition for Production Use

Enter in `Docker-compose` directory and make required directories for local mounts:
```bash
cd Docker-compose
mkdir -p ./mongo/db          # DB Data directory
mkdir -p ./iam-proxy-italia-project   # iam-proxy-italia data instance
mkdir -p ./djangosaml2_sp    # Service provider directory
mkdir -p ./nginx/html/static # static files for nginx
```

Copy required files
```bash
cp -R ../iam-proxy-italia-project/* ./iam-proxy-italia-project
cp -R ../iam-proxy-italia-project-demo-examples/djangosaml2_sp/* ./djangosaml2_sp
cp -E ../iam-proxy-italia-project/static/* ./nginx/html/static
```

Clean static data from Satosa project
```bash
rm -R ./iam-proxy-italia-project/static
```

Copy the example env file and edit according to your configuration,
therefore **all the default passwords MUST be changed**.

```bash
cp env.example .env
```
You can still edit all files in detail from their local volumes.

Run the compose for a minimal system (nginx and satosa)
```
docker compose up
```

Run the full demo
```bash
docker compose --profile demo up
```

Read the [profiles guide](./docker_compose_profiles.md) for more information.

## Configure your host for the demo

When running the full demo (with trust-anchor, CIE provider, and relying party ... all the backends and frontends ...), the compose setup uses the hostname `iam-proxy-italia.example.org` for SATOSA and related hostnames for other services. These requirements apply to the entire project, not just individual backends or frontends.

### Edit .env (SATOSA_HOSTNAME)

If copying from `env.example`, ensure `SATOSA_HOSTNAME` is set:

```
SATOSA_HOSTNAME=iam-proxy-italia.example.org
```

### Hosts file

Add the following entries to your hosts file (`/etc/hosts` on Linux/macOS, `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
127.0.0.1		cie-provider.example.org
127.0.0.1		trust-anchor.example.org
127.0.0.1		iam-proxy-italia.example.org
```

### Certificates

`Docker-compose/certbot/live/iam-proxy-italia.example.org` will be created automatically by the compose setup, so that TLS works for the new hostname.

### Insights

* More details on profiles read the [Docker Compose Profiles](./docker_compose_profiles.md) page
* More details on run-docker-compose.sh read the [run-docker-compose.sh](./run-docker-compose.md) page
* MongoDB env vars (backend vs frontend, shared defaults): [docs/mongodb-env.md](./mongodb-env.md)
* For common issues (containers, certificates, MongoDB): [docs/TROUBLESHOOTING.md](./TROUBLESHOOTING.md)
