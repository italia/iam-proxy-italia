
## Setup Instructions

### Automated Setup with Docker-Compose
The installation process is completely automated by the script `run-docker-compose.sh` located in the `Docker-compose` folder.
You can set the variable `COMPOSE_PROFILES` to the value `wwwallet` into the script and run it with the command:
```bash
./run-docker-compose.sh
```

### Trusted Issuer Configuration
After the backend initialization, you must add the instance of the OpenID4VCI frontend, distributed in iam-proxy-italia using [pyeudiw](https://github.com/italia/eudi-wallet-it-python), as trusted issuer.
We therefore need to configure the enabled credential issuer by adding an entry in the table `credential_issuer` of the Mysql database used by wwwallet backend.
You can do this with any MariaDB client or using the MariaDB command line.
Note that the url must point to the OpenID4VCI Frontend to work properly.
An example of the SQL command to be executed is the following:
```sql
INSERT INTO wwwalletdb.credential_issuer (credentialIssuerIdentifier,clientId,visible)
	VALUES ('Satosa OpenID4VCI','https://localhost/OpenID4VCI',1);
```