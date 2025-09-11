## Prerequisites
- Docker and Docker Compose installed on your machine.
- An instance of Mysql greater or equal to version 8.

## Setup Instructions
To set up an instance of wwwallet, the source code of the frontend and backend must be cloned from the respective GitHub repositories.
The frontend and backend can be run using Docker. Below are the steps to set up and run wwwallet.

1. Clone the repositories:
```bash
git clone https://github.com/wwWallet/wallet-backend-server.git
git clone https://github.com/wwWallet/wallet-frontend.git
```

2. Navigate to the backend directory and edit the file `config/config.template.ts` to set the environment variables according to your requirements. 
Note that you will need to set: 
- the host and port where the backend will be running.
- the database connection details to connect to your Mysql instance.
- and the notification system need to be disabled if no firebase subscription is available.

This is an example configuration for a local hosted instance:
```typescript
export const config = {
	url: "localhost",
	port: "8002",
	appSecret: "SERVICE_SECRET",
	ssl: false,
	db: {
		host: "localhost",
		port: "3306",
		username: "root",
		password: "changeme",
		dbname: "test",
	},
	walletClientUrl: "WALLET_CLIENT_URL",
	webauthn: {
		attestation: "direct",
		origin: "WEBAUTHN_ORIGIN",
		rp: {
			id: "WEBAUTHN_RP_ID",
			name: "wwWallet demo",
		},
	},
	alg: "EdDSA",
	notifications: {
		enabled: false,
		serviceAccount: "firebaseConfig.json"
	}
}
```

3. Build and run the backend Docker container:
```bash
cd wallet-backend-server
docker build -t wwwallet-backend .
docker run -d -p 8002:8002 --name wwwallet-backend wwwallet-backend
```

4. After the backend initialization, you must add the instance of iam-proxy-italia as trusted issuer. 
To do this, you need to add the entry in the table `credential_issuer` of the Mysql database used by the backend.
You can do this with any Mysql client or using the Mysql command line.
Note that the url must point to the openid frontend to work properly.


5. Navigate to the frontend directory and run yarn to install and run dependencies:
```bash
cd ../wallet-frontend
yarn install
yarn start
```

6. The frontend will be available at `http://localhost:3000` by default.

## Troubleshooting the self-signed certificate
If you are using a self-signed certificate for the backend, you may encounter issues with the frontend not being able to connect to the backend due to certificate validation errors.
To resolve this, you can overwrite the file backend at path `src/router/proxy.router.ts` with the following code:
```typescript
import axios from 'axios';
import express, { Request, Response, Router } from 'express';
import { Agent } from 'node:https';
const proxyRouter: Router = express.Router();

const agent = new Agent({
    rejectUnauthorized: false,
});

proxyRouter.post('/', async (req, res) => {
	const { headers, method, url, data } = req.body;
	try {
		const isBinaryRequest = /\.(png|jpe?g|gif|webp|bmp|tiff?|ico)(\?.*)?(#.*)?$/i.test(url);
		console.log("URL = ", url)
		const response = await axios({
			url: url,
			headers: headers,
			method: method,
			data: data,
			...(isBinaryRequest && { responseType: 'arraybuffer' }),
			maxRedirects: 0,
			httpsAgent: agent,
		});

		if (isBinaryRequest) {
			// forward all response headers
			for (const key in response.headers) {
				if (Object.prototype.hasOwnProperty.call(response.headers, key)) {
					const value = response.headers[key];
					if (value !== undefined) {
						res.setHeader(key, value as string);
					}
				}
			}
			return res.status(response.status).send(response.data);
		}

		// JSON or other text content
		return res.status(response.status).send({
			status: response.status,
			headers: response.headers,
			data: response.data,
		});
	}
	catch (err) {
		console.error("Error in proxy request: ", err);
		if (err.response && err.response.data) {
			console.error("Error data = ", err.response.data)
		}
		if (err.response && err.response.status == 302) {
			return res.status(200).send({ status: err.response.status, headers: err.response.headers, data: {} })
		}
		return res.status(err.response?.status ?? 104).send({ status: err.response?.status ?? 104, data: err.response?.data, headers: err.response?.headers });
	}
})

export {
	proxyRouter
}
```

