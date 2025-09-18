export const config = {
	url: "localhost",
	port: "8002",
	appSecret: "SERVICE_SECRET",
	ssl: false,
	db: {
		host: "wwwallet-mariadb",
		port: "3306",
		username: "root",
		password: "changeme",
		dbname: "wwwalletdb",
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
