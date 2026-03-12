# Setup

## Table of Contents
1. [Install and configure](#install-and-configure)
2. [Using Docker](#using-docker)

## Install and configure

````
wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
sudo apt update
sudo apt install -y mongodb-org
sudo apt install mongosh
````

#### Connect to MongoDB
````
mongosh mongodb://root:example@172.21.0.3:27017
````

#### create satosa user grants
````
use oidcop
db.createUser(
  {
    user: "satosa",
    pwd:  "thatpassword",
    roles: [
        { role: "readWrite", db: "oidcop" }
    ]
  }
)

exit
````

For **OIDC client and session indexes** and **inserting test clients** (e.g. `jbxedfmfyc`), see [satosa_oidcop_oidc_client_registration.md](satosa_oidcop_oidc_client_registration.md).

### Using Docker

When using docker-compose in [docker-compose.md](docker-compose.md) all operations described in section  [Install and configure](#install-and-configure) are executed  by the init script [init-mongo.sh](../Docker-compose/mongo/init-mongo.sh) at the first start o the container.

#### set environment in .env

- MONGO_DBUSER : user admin of oidcop DB in Mongo;
- MONGO_DBPASSWORD : password of user MONGO_DBUSER;

This two environment variable are used in 3 of our container.

#### docker-compose.yml environments for MONGODB

Before run the docker-compose, please configure all environment [here](setup.md#configuration-by-environment-variables) 

##### satosa-mongo

````
    environment:
      MONGO_INITDB_DATABASE: oidcop
      MONGO_INITDB_ROOT_USERNAME: "${MONGO_DBUSER}"
      MONGO_INITDB_ROOT_PASSWORD: "${MONGO_DBPASSWORD}"
````

- MONGO_INITDB_DATABASE : name of a database to be used for creation scripts;
- MONGO_INITDB_ROOT_USERNAME : name of the user created which have the role of 'root' (superuser role); 
- MONGO_INITDB_ROOT_PASSWORD : password off the MONGO_INITDB_ROOT_USERNAME.

##### satosa-mongo-express

````
    environment:
      ME_CONFIG_BASICAUTH_USERNAME: satosauser
      ME_CONFIG_BASICAUTH_PASSWORD: satosapw
      ME_CONFIG_MONGODB_ADMINUSERNAME: "${MONGO_DBUSER}"
      ME_CONFIG_MONGODB_ADMINPASSWORD: "${MONGO_DBPASSWORD}"
      ME_CONFIG_MONGODB_URL: mongodb://${MONGO_DBUSER}:${MONGO_DBPASSWORD}@satosa-mongo:27017/
````

- ME_CONFIG_BASICAUTH_USERNAME : mongo-express web username;
- ME_CONFIG_BASICAUTH_PASSWORD : mongo-express web password;
- ME_CONFIG_MONGODB_ADMINUSERNAME : MongoDB admin username;
- ME_CONFIG_MONGODB_ADMINPASSWORD : MongoDB admin password;
- ME_CONFIG_MONGODB_URL : MongoDB connection URL.


