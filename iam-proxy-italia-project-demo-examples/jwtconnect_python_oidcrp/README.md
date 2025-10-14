Start the Relying-Party
-----------------------

Clone and install [JWTConnect-Python-OidcRP](https://github.com/identitypython/JWTConnect-Python-OidcRP) as follow:
```
git clone https://github.com/IdentityPython/JWTConnect-Python-OidcRP.git
cd JWTConnect-Python-OidcRP

# create a virtualenv to avoid installing it systemwide
virtualenv -ppython3 env
source env/bin/activate

# install it in the current environment
pip install -e .

# then install flask
pip install flask

# enter in the example folder
cd example

python3 -m flask_rp.wsgi ../../Satosa-saml2saml/iam-proxy-italia-project_sp/jwtconnect_python_oidcrp/satosa.json
````

You should see an output like this
````
2023-02-23 22:06:15,893 root DEBUG Configured logging using dictionary
 * Serving Flask app 'oidc_rp'
 * Debug mode: on
2023-02-23 22:06:15,929 werkzeug INFO WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on https://localhost:8090
2023-02-23 22:06:15,929 werkzeug INFO Press CTRL+C to quit
2023-02-23 22:06:15,930 werkzeug INFO  * Restarting with stat
2023-02-23 22:06:16,093 root DEBUG Configured logging using dictionary
2023-02-23 22:06:16,129 werkzeug WARNING  * Debugger is active!
2023-02-23 22:06:16,129 werkzeug INFO  * Debugger PIN: 113-267-765

````

then go to `https://127.0.0.1:8090`

## Configure webserver with satosa.json
Most important webserver configurations are:
* `webserver`: contain a collection of all webserver configuration
* `webserver.port`: webserver port, preconfigured 8090
* `webserver.domain`: webserver domain, preconfigured 'localhost'
* `webserver.server_cert`: webserver public certificate, preconfigured 'certs/cert.pem'
* `webserver.server_key`: webserver private key, preconfigured 'certs/key.pen'
* `webserver.debug`: debug webserver request, preconfigured true

## Configure rp with satosa.json
The RP is fully configurable with a simple json. Most important client config are:
* `port`: rp port, preconfigured 8090
* `domain`: rp domain, preconfigured 'localhost'
* `base_url`: rp base url, preconfigured 'https://example.org'
* `httpc_params.verify`: check certificate, preconfigured false
* `client.services`: contain a collection of configured OP, each key is an op with his configuration as value

## Configure an OP with satosa.json
Each key in `client.services` is a OP, in this example the OP is named `satosa`. most important OP configs are:
* `client.services.satosa.issuer`: OP issuer url, preconfigured 'https://localhost:10000'
* `client.services.satosa.client_id`: Unique identifier for RP, preconfigured 'jbxedfmfyc'
* `client.services.satosa.client_salt`: Salt for secret
* `client.services.satosa.client_secret`: Secret
* `client.services.satosa.application_type`: type of application, preconfigured 'web'
* `client.services.satosa.token_endpoint_auth_method`: authentication method, preconfigured 'client_secret_basic'
* `client.services.satosa.jwks_uri`: url of jwks config, preconfigured 'https://localhost:8090/static/jwks.json'
* `client.services.satosa.redirect_uris`: Array of redirect url,  preconfigured ["https://localhost:8090/authz_cb/satosa"]
* `client.services.satosa.grant_types`: Array of permitted grant type, preconfigured ["authorization_code"]
* `client.services.satosa.allowed_scopes`: array of allowed scope, preconfigured ["openid", "profile", "email", "offline_access"]
