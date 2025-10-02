# Docker Compose

## Table of Contents

1. [Requirements](#requirements)
2. [Run the composition - MAGIC WAY](#run-the-composition-magic-way)
3. [Run the composition - LONG WAY](#run-the-composition-long-way)
4. [Configure your system](#configure-your-system)
5. [Insights](#Insights)

## Requirements

In order to execute the run script you need:

* docker-compose

Installation example in Ubuntu:

```
sudo apt install docker-compose
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
-`w` to run the wwwallet profile, view [wwwallet_setup](../docs/readme.wwwallet_setup.md) for more details.

> ⚠️ Warning: The script deletes any previous created directory if found.

> ℹ️ **Note:**   
> To install `spid_sp_test`, run `pip install git+https://github.com/italia/spid-sp-test.git` or `pip install spid-sp-test`.

The result is represented by the following services:

* iam-proxy-italia is published with nginx frontend on https://localhost
* Mongo Espress is published on http://localhost:8081
* Django SAML2 SP is published on https://localhost:8000
* Spid-samlcheck is published on https://localhost:8443

More details ad start option are avable on [run-docker-compose.sh](../docs/run-docker-compose.sh.md) page

### Run the Composition for Production Use

Enter in `Docker-compose` directory and make required direcotries for local mounts:
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
cp -R ../iam-proxy-italia-project_sp/djangosaml2_sp/* ./djangosaml2_sp
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

Read the [profiles guide](../docs/docker_compose_profiles.md) for more informations 

### Insights

* More details on prodiles read the [Docker Compose Profiles](../docs/docker_compose_profiles.md) page
* More details on run-docker-compose,sh read the [run-docker-compose.sh](../docs/run-docker-compose.sh.md) page
