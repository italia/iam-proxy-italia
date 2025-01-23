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

#### make client_id unique

````
db.client.createIndex( { "client_id": 1 }, { unique: true } )
db.client.createIndex( { "registration_access_token": 1 }, { unique: true } )
````

#### make access_token and sid unique

````
db.session.createIndex( { "sid": 1 }, { unique: true } )
````

#### create expired session deletion

Prune all the expired sessions automatically, keeping only the last two entries.

````
db.session.createIndex(
  { expires_at: 1 },
  { expireAfterSeconds: 0, partialFilterExpression: { count: { $gt: 2 } } }
);
````

#### insert a test client like this

````
db.client.insertOne(
    {"client_id": "jbxedfmfyc", "client_name": "ciro", "client_salt": "6flfsj0Z", "registration_access_token": "z3PCMmC1HZ1QmXeXGOQMJpWQNQynM4xY", "registration_client_uri": "https://localhost:10000/registration_api?client_id=jbxedfmfyc", "client_id_issued_at": 1630952311.410208, "client_secret": "19cc69b70d0108f630e52f72f7a3bd37ba4e11678ad1a7434e9818e1", "client_secret_expires_at": 1662488311.410214, "application_type": "web", "contacts": ["ops@example.com"], "token_endpoint_auth_method": "client_secret_basic", "redirect_uris": [["https://localhost:8090/authz_cb/satosa", {}]], "post_logout_redirect_uris": [["https://localhost:8090/session_logout/satosa", null]], "response_types": ["code"], "grant_types": ["authorization_code"], "allowed_scopes": ["openid", "profile", "email", "offline_access"]}
)
````

### Using Docker

When using docker-compose in [Docker-compose](./Docker-compose) all operations described in section  [Install and configure](#install-and-configure) are executed  by the init script [init-mongo.sh](./compose-Satosa-Saml2Spid/init-mongo.sh) at the first start o the container.

#### set environment in .env

- MONGO_DBUSER : user admin of oidcop DB in Mongo;
- MONGO_DBPASSWORD : password of user MONGO_DBUSER;

This two environment variable are used in 3 of our container.

#### docker-compose.yml environments for MONGODB

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


