
## Setup Instructions

### Automated Setup with Docker-Compose
The installation process is completely automated by the script `run-docker-compose.sh` located in the `Docker-compose` folder.
You can set the variable `COMPOSE_PROFILES` to the value `wwwallet` into the script and run it with the command:
```bash
./run-docker-compose.sh
```

### Trusted Issuer Configuration
After the backend initialization, you must add the instance of iam-proxy-italia as trusted issuer.
To do this, you need to add the entry in the table `credential_issuer` of the MariaDB database used by the backend.
You can do this with any MariaDB client or using the MariaDB command line.
Note that the url must point to the openid frontend to work properly.