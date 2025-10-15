
# Setup Instructions

## Prerequisites
Before you begin, ensure you have the following installed:
- Docker
- Docker Compose
- Git

### WWWAllet Backend Setup
Every aspect of backend configuration is managed through `iam-proxy-italia-project/wwwallet/configs/config.template.ts` file and if you need to customize it, like changing the database connection details or enabling/disabling certain features, you can do so by editing this file.
Note that you will need to set: 
- the host and port where the backend will be running.
- the database connection details to connect to your Mysql instance.
- and the notification system need to be disabled if no firebase subscription is available.

### WWWAllet Frontend Setup
The frontend configuration is managed through the `iam-proxy-italia-project/wwwallet/configs/.env.prod` file.
You can customize it by editing this file.
Note that you will need to set:
- the backend url to connect to the backend instance.
- the firebase configuration if you want to enable the notification system.

### Nginx Custom Configuration
The Nginx configuration for wwwallet is managed through the `iam-proxy-italia-project/wwwallet/configs/wwwallet.conf` file.
If you change the backend or frontend host and port, you will need to update this file accordingly.

## Installation Steps

### Automated Setup with Docker-Compose
The installation process is completely automated by the script `run-docker-compose.sh` located in the `Docker-compose` folder.
You can set the variable `COMPOSE_PROFILES` to the value `wwwallet` into the script and run it with the command:
```bash
./run-docker-compose.sh -w
```

### Trusted Issuer Configuration
After the backend initialization, you must add the instance of the OpenID4VCI frontend, distributed in iam-proxy-italia using [pyeudiw](https://github.com/italia/eudi-wallet-it-python), as trusted issuer.
We therefore need to configure the enabled credential issuer by adding an entry in the table `credential_issuer` of the Mysql database used by wwwallet backend.
You can do this with any MariaDB client or using the MariaDB command line.
Note that the url must point to the OpenID4VCI Frontend to work properly.
An example of the SQL command to be executed is the following:
```sql
INSERT INTO wwwalletdb.credential_issuer (clientId,credentialIssuerIdentifier,visible)
	VALUES ('Satosa OpenID4VCI','https://localhost/OpenID4VCI',1);
```