# Setup

In this section there are all the required information to install, configure and run iam-proxy-italia. For common issues and solutions, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### NGINX setup

A valid ssl certificate is needed, to add your certificate you have to override the `/etc/nginx/certs` directory with your docker volume, containing your certificates.

## Setup

###### Dependencies Ubuntu

```bash
sudo apt install -y libffi-dev libssl-dev python3-pip xmlsec1 procps libpcre3 libpcre3-dev
```

###### Dependencies Centos/RHEL

```bash
sudo yum install -y libffi-devel openssl-devel python3-pip xmlsec1 procps pcre pcre-devel
sudo yum groupinstall "Development Tools"
sudo yum install -y python3-wheel python3-devel
```

###### Prepare environment

Within the directory `/{your path}/iam-proxy-italia` execute the following commands:

```bash
pip install --upgrade pip
pip install flake8 pipx poetry
pip install --upgrade packaging
poetry config virtualenvs.in-project true
poetry install
source .venv/bin/activate
pip install "spid-sp-test>=1.2.17"

mkdir satosa_proxy && cd satosa_proxy

git clone https://github.com/italia/iam-proxy-italia.git repository
cd repository

poetry install
poetry env info
```

**Installation recommendation:** For full setup (all plugins, SPID/CIE, etc.) use **poetry** as above. For running tests only, from the project root use **poetry**: `poetry install --extras test` (see [testing.md](testing.md)).


## Configure the Proxy

- Create certificates for SPID, using [spid-compliant-certificates](https://github.com/italia/spid-compliant-certificates) or [spid-compliant-certificates-python](https://github.com/italia/spid-compliant-certificates-python)
- Copy `repository/iam-proxy-italia-project/*` contents (`cp -R repository/iam-proxy-italia-project/* .`) and **edit the files below** 

  - `proxy_conf.yaml`
  - `conf/backends/spidsaml2_backend.yaml`
  - `conf/backends/saml2_backend.yaml`
  - `conf/frontend/saml2_frontend.yaml`
  - `conf/frontend/oidc_op_frontend.yaml` (optional to enable OIDC Provider)

Remember to:

* edit and customize all the values like `"CHANGE_ME!"` in the configuration files, in `proxy_conf.yaml` and in the configurations of the plugins.
* set the $HOSTNAME environment with the production DNS name
* set all key and salt with your secret key ($SATOSA_ENCRYPTION_KEY, $SATOSA_SALT)
* set a new MongoDB password ($MONGO_DBUSER, $MONGO_DBPASSWORD)
* set a new certificate for SAML / SPID ($SATOSA_PUBLIC_KEYS, $SATOSA_PRIVATE_KEYS)
* add valid data for  metadata, read [Configurations by environments](#configuration-by-environment-variables)

### OIDC

This project uses [SATOSA_oidcop](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop) as OAuth2/OIDC frontend module.

Comment/uncomment the following statement in the proxy_configuration to enable it.


### Configuration by environment variables

You can override the configuration of the proxy by setting one or more of the following environment variables, grouped by scope.

#### General proxy configuration

| **Environment var**                   | **Description**                                            | **Example Value**              |
|--------------------------------------|------------------------------------------------------------|--------------------------------|
| **BASE_DIR**                         | Base directory for SATOSA proxy                            | /satosa_proxy                  |
| **SATOSA_BY_DOCKER**                 | SATOSA configuration when run by Docker                    | 1                              |
| **SATOSA_BASE**                      | Base URL of SATOSA server                                  | https://$HOSTNAME              |
| **SATOSA_BASE_STATIC**               | Base URL of SATOSA static assets                           | https://$HOSTNAME/static       |
| **SATOSA_DISCO_SRV**                 | Discovery page URL for all backends                        | https://$HOSTNAME/static/disco.html |
| **SATOSA_UNKNOW_ERROR_REDIRECT_PAGE**| Redirect page for unknown errors                           | https://$HOSTNAME/static/error_page.html |
| **SATOSA_ENCRYPTION_KEY**            | Encryption key for state and OIDC tokens                   | CHANGE_ME!                     |
| **SATOSA_SALT**                      | General-purpose salt for hashing/encryption                | CHANGE_ME!                     |
| **SATOSA_STATE_ENCRYPTION_KEY**      | State encryption key                                       | CHANGE_ME!                     |
| **SATOSA_USER_ID_HASH_SALT**         | User ID hash salt                                          | CHANGE_ME!                     |

#### SAML2 / SPID / CIE backends

These variables configure organization and contact metadata, SAML keys, and metadata download flags for SAML2, SPID and CIE backends.

| **Environment var**                         | **Description**                                            | **Example Value**               |
|--------------------------------------------|------------------------------------------------------------|---------------------------------|
| **SATOSA_PRIVATE_KEY**                     | Private key for SAML2 / SPID backends                      | ${KEYS_FOLDER}/privkey.pem      |
| **SATOSA_PUBLIC_KEY**                      | Public key for SAML2 / SPID backends                       | ${KEYS_FOLDER}/cert.pem         |
| **SATOSA_ORGANIZATION_DISPLAY_NAME_EN**    | English organization display name                          | Resource provided by Example Organization |
| **SATOSA_ORGANIZATION_DISPLAY_NAME_IT**    | Italian organization display name                          | Resource provided by Example Organization |
| **SATOSA_ORGANIZATION_NAME_EN**            | English full organization name                             | Resource provided by Example Organization |
| **SATOSA_ORGANIZATION_NAME_IT**            | Italian full organization name                             | Resource provided by Example Organization |
| **SATOSA_ORGANIZATION_URL_EN**             | English organization URL                                   | https://example_organization.org |
| **SATOSA_ORGANIZATION_URL_IT**             | Italian organization URL                                   | https://example_organization.org |
| **SATOSA_CONTACT_PERSON_EMAIL_ADDRESS**    | Contact person email                                       | support.example@organization.org |
| **SATOSA_CONTACT_PERSON_TELEPHONE_NUMBER** | Contact person telephone number for SPID / CIE backends    | +3906123456789                  |
| **SATOSA_CONTACT_PERSON_FISCALCODE**       | Contact person fiscal code for SPID / CIE backends         | 01234567890                     |
| **SATOSA_CONTACT_PERSON_GIVEN_NAME**       | Contact person name                                        | Name                            |
| **SATOSA_CONTACT_PERSON_IPA_CODE**         | Contact person IPA code for SPID / CIE backends            | ipa00c                          |
| **SATOSA_CONTACT_PERSON_MUNICIPALITY**     | Contact person municipality code for CIE backend           | H501                            |
| **SATOSA_GET_IDEM_MDQ_KEY**                | Flag for getting IDEM MDQ key                              | true                            |
| **SATOSA_GET_SPID_IDP_METADATA**           | Flag for getting SPID IdP metadata                         | true                            |
| **SATOSA_GET_CIE_IDP_METADATA**            | Flag for getting CIE IdP metadata                          | true                            |
| **SATOSA_GET_FICEP_IDP_METADATA**          | Flag for getting FICEP (eIDAS) IdP metadata                | true                            |

#### SAML2 frontends (UI metadata and keys)

These variables control UI-related metadata (names, descriptions, URLs, logo) exposed by SAML2 frontends.  
SAML2 frontends also rely on the same SAML keys configured for backends (`SATOSA_PRIVATE_KEY`, `SATOSA_PUBLIC_KEY`).

| **Environment var**                    | **Description**                           | **Example Value**                               |
|----------------------------------------|-------------------------------------------|-------------------------------------------------|
| **SATOSA_UI_DESCRIPTION_EN**           | English UI description                    | Resource description                            |
| **SATOSA_UI_DESCRIPTION_IT**           | Italian UI description                    | Resource description                            |
| **SATOSA_UI_DISPLAY_NAME_EN**          | English UI display name                   | Resource Display Name                           |
| **SATOSA_UI_DISPLAY_NAME_IT**          | Italian UI display name                   | Resource Display Name                           |
| **SATOSA_UI_INFORMATION_URL_EN**       | English UI information URL                | https://example_organization.org/information_url_en |
| **SATOSA_UI_INFORMATION_URL_IT**       | Italian UI information URL                | https://example_organization.org/information_url_en |
| **SATOSA_UI_PRIVACY_URL_EN**           | English UI privacy URL                    | https://example_organization.org/privacy_en     |
| **SATOSA_UI_PRIVACY_URL_IT**           | Italian UI privacy URL                    | https://example_organization.org/privacy_en     |
| **SATOSA_UI_LOGO_URL**                 | Logo URL                                  | https://example_organization.org/logo.png       |
| **SATOSA_UI_LOGO_HEIGHT**              | Logo height                               | 60                                              |
| **SATOSA_UI_LOGO_WIDTH**               | Logo width                                | 80                                              |

#### OIDC (CIE OIDC backend, OIDCOP frontend)

MongoDB env vars for OIDC components: `MONGO_CIE_OIDC_BACKEND_*` (CIE OIDC backend), `MONGO_OIDCOP_*` (oidcop frontend). For a single MongoDB, set `MONGO_URL`, `MONGO_PORT`, `MONGO_DBUSER`, `MONGO_DBPASSWORD`; component vars fall back to these. See [mongodb-env.md](mongodb-env.md).

**Shared defaults:** `MONGO_URL`, `MONGO_PORT`, `MONGO_DBUSER`, `MONGO_DBPASSWORD`

**OIDC component overrides:** `MONGO_CIE_OIDC_BACKEND_URL`, `MONGO_OIDCOP_URL` (and `_PORT`, `_DBUSER`, `_DBPASSWORD`). CIE OIDC also has `MONGO_CIE_OIDC_BACKEND_DB_NAME`, `MONGO_CIE_OIDC_BACKEND_AUTH_COLLECTION`, `MONGO_CIE_OIDC_BACKEND_TOKEN_COLLECTION`, `MONGO_CIE_OIDC_BACKEND_USER_COLLECTION`.

#### OpenID4VC (pyeudiw: OpenID4VP backend, OpenID4VCI frontend)

MongoDB env vars for OpenID4VC (pyeudiw) components: `MONGO_PYEUDIW_OPENID4VP_*` (OpenID4VP backend), `MONGO_PYEUDIW_OPENID4VCI_*` (OpenID4VCI frontend). Same shared defaults as above.

**OpenID4VC component overrides:** `MONGO_PYEUDIW_OPENID4VP_URL`, `MONGO_PYEUDIW_OPENID4VCI_URL` (and `_PORT`, `_DBUSER`, `_DBPASSWORD`).

For a complete description of pyeudiw configuration, refer to the upstream `eudi-wallet-it-python` documentation: [OpenID4VP backend](https://italia.github.io/eudi-wallet-it-python/rst/pyeudiw.satosa.backends.html), [OpenID4VCI frontend](https://italia.github.io/eudi-wallet-it-python/rst/pyeudiw.satosa.frontends.html).



### Generate JWK for metadata_jwks

Convert the Leaf private key into JWK format:

```python
from jwcrypto import jwk
import json

with open("leaf.key","rb") as f:
    key = jwk.JWK.from_pem(f.read())

key_dict = json.loads(key.export_private())
key_dict["use"] = "sig"
key_dict["alg"] = "RS256"
key_dict["kid"] = "uid-x-y-z"

print(json.dumps(key_dict, indent=2))
```
Copy the generated output into `metadata_jwks`.

### YAML Configuration: metadata_jwks

```yaml
metadata_jwks:
  - kty: RSA
    use: sig
    alg: RS256
    kid: uid-x-y-z
    n: <generated_value>
    e: AQAB
    d: <generated_value>
    p: <generated_value>
    q: <generated_value>
    dp: <generated_value>
    dq: <generated_value>
    qi: <generated_value>
```

### Recommendations
For production environments:
* Rotate keys periodically


### Saml2 Metadata

If you want to handle metadata file manually create the `metadata/idp` and `metadata/sp` directories, then copy the required metadata:

```bash
mkdir -p metadata/idp metadata/sp
wget https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml -O metadata/idp/spid-entities-idps.xml
```

Copy your SP metadata to your Proxy

```bash
wget https://sp.fqdn.org/saml2/metadata -O metadata/sp/my-sp.xml
```

Otherwise the best method would be enabling a MDQ server in each frontend and backend configuration file.
See `iam-proxy-italia-project/conf/{backends,frontends}/$filename` as example.

### Get SPID backend metadata

The proxy backend exposes its SPID metadata at the following url (customizable):

```text
https://iam-proxy-italia.example.org/spidSaml2/metadata
```

### Get Proxy Fronted Metadata for your SP

The Proxy metadata must be configured in your SP. Your SP is an entity that's external from this Proxy, eg: shibboleth sp, djangosaml2, another ...

```bash
wget https://iam-proxy-italia.example.org/Saml2IDP/metadata -O path/to/your/sp/metadata/satosa-spid.xml --no-check-certificate
```

### spid-saml-check

Load spid-saml-check metadata:

```bash
wget https://localhost:8443/metadata.xml -O metadata/idp/spid-saml-check.xml --no-check-certificate
```

Start an authentication from your SP.

Load metadata from `https://iam-proxy-italia.example.org/spidSaml2/metadata`.

![result](../gallery/screen.gif)
**Figure 2**: The result using spid-saml-check.

## First Run

That's the stdout log of a working instance of SATOSA in uwsgi

```text
*** Starting uWSGI 2.0.19.1 (64bit) on [Tue Mar 30 17:08:49 2021] ***
compiled with version: 9.3.0 on 11 September 2020 23:11:42
os: Linux-5.4.0-70-generic #78-Ubuntu SMP Fri Mar 19 13:29:52 UTC 2021
nodename: wert-desktop
machine: x86_64
clock source: unix
pcre jit disabled
detected number of CPU cores: 8
current working directory: /path/to/IdentityPython/satosa_proxy
detected binary path: /path/to/IdentityPython/satosa_proxy/satosa.env/bin/uwsgi
your processes number limit is 62315
your memory page size is 4096 bytes
detected max file descriptor number: 1024
lock engine: pthread robust mutexes
uWSGI http bound on 0.0.0.0:10000 fd 4
spawned uWSGI http 1 (pid: 28676)
uwsgi socket 0 bound to TCP address 127.0.0.1:39553 (port auto-assigned) fd 3
Python version: 3.8.5 (default, Jan 27 2021, 15:41:15)  [GCC 9.3.0]
Python main interpreter initialized at 0x55f744576790
your server socket listen backlog is limited to 100 connections
your mercy for graceful operations on workers is 60 seconds
mapped 72920 bytes (71 KB) for 1 cores
*** Operational MODE: single process ***
[2021-03-30 17:08:50] [INFO ]: Running SATOSA version 7.0.1 [satosa.proxy_server.make_app:165]
[2021-03-30 17:08:50] [INFO ]: Loading backend modules... [satosa.base.__init__:42]
[2021-03-30 17:08:51] [INFO ]: Setup backends: ['Saml2', 'spidSaml2'] [satosa.plugin_loader.load_backends:49]
[2021-03-30 17:08:51] [INFO ]: Loading frontend modules... [satosa.base.__init__:45]
[2021-03-30 17:08:51] [INFO ]: Setup frontends: ['Saml2IDP'] [satosa.plugin_loader.load_frontends:70]
[2021-03-30 17:08:51] [INFO ]: Loading micro services... [satosa.base.__init__:51]
[2021-03-30 17:08:51] [INFO ]: Loaded request micro services: ['DecideBackendByTarget'] [satosa.plugin_loader.load_request_microservices:260]
[2021-03-30 17:08:51] [INFO ]: Loaded response micro services:[] [satosa.plugin_loader.load_response_microservices:281]
WSGI app 0 (mountpoint='') ready in 2 seconds on interpreter 0x55f744576790 pid: 28675 (default app)
*** uWSGI is running in multiple interpreter mode ***
spawned uWSGI worker 1 (and the only) (pid: 28675, cores: 8)
```
