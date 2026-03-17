## Copy required files
````
export DESTDIR="saml2-saml2"
mkdir -p $DESTDIR/plugins

cp SATOSA/example/{proxy_conf.yaml.example,internal_attributes.yaml.example} $DESTDIR/
````

#### Plugins
The authentication protocol specific communication is handled by different plugins, divided into frontends (receiving requests from clients) and backends (sending requests to target providers).
````
cp SATOSA/example/plugins/frontends/saml2_frontend.yaml.example $DESTDIR/plugins/
cp SATOSA/example/plugins/backends/saml2_backend.yaml.example $DESTDIR/plugins/
````

## Create Frontend and Backend certificates
````
FQDN="satosa.testunical.it"
openssl req -nodes -new -x509 -days 3650 -keyout frontend.key -out frontend.cert -subj '/CN=$FQDN'
openssl req -nodes -new -x509 -days 3650 -keyout backend.key -out backend.cert -subj '/CN=$FQDN'
````

## Configure the proxy
Edit alle the *.yaml.example files according to [official Documentation](https://github.com/IdentityPython/SATOSA/blob/master/doc/README.md#configuration), renaming them without .example suffix.

#### proxy_conf.yaml
[Documentation](https://github.com/IdentityPython/SATOSA/blob/master/doc/README.md#satosa-proxy-configuration-proxy_confyamlexample)
Variables that must be edited:
````
BASE: https://a fully qualified domain name
INTERNAL_ATTRIBUTES: file with mapping, see next paragraph.
COOKIE_STATE_NAME: custom or default name, change it for disabling server fingerpint!
STATE_ENCRYPTION_KEY: alphadecimal secret, change it for security!
````

#### internal_attributes.yaml
A list of external attributes names which should be mapped to the internal attributes.

## Run

Produce metadata
````
satosa-saml-metadata proxy_conf.yaml ./pki/backend.key ./pki/backend.cert --split-backend --dir metadata/

Writing metadata to 'metadata/frontend.xml'
Writing metadata to 'metadata/Saml2_0.xml'
Writing metadata to 'metadata/spidSaml2_0.xml'

````

Copy metadata, this is only for test, the use pyFF or other MDX server is suggested.
````
# in test sp
wget https://satosa.testunical.it:10000/Saml2IDP/metadata -O saml2_sp/saml2_config/satosa_frontend.xml --no-check-certificate

# in test idp
wget https://satosa.testunical.it:10000/Saml2/metadata -O idp/saml2_config/metadata/satosa_backend.xml --no-check-certificate

# in test spid-testenv2
wget https://satosa.testunical.it:10000/spidSaml2/metadata  -O conf/satosa_metadata.xml --no-check-certificate

# in satosa
# ...It would be better to use a mdq server like pyff, see examples.
````

Run in debug mode, `--reload` will restart process if source code changes
````
gunicorn -b0.0.0.0:10000 satosa.wsgi:app --keyfile=./pki/frontend.key --certfile=./pki/frontend.cert  --reload

# run with uwsgi if you prefer, --honour-stdin needs for debugging with pdb
uwsgi --wsgi-file ../apps/SATOSA/src/satosa/wsgi.py  --https 0.0.0.0:10000,./pki/frontend.cert,./pki/frontend.key --callable app --honour-stdin

# in uwsgi_setup there a some production examples, the following is to debug with pdb a satosa running whit that configuration
uwsgi --ini uwsgi_setup/uwsgi.ini --honour-stdin
````

Give Metadata to your endpoints, SP and IDP.
backend.xml to target IDP, frontend.xml to SP... It would be better if they use a MDQ server.
````
cat frontend.xml > ../djangosaml2_sp/saml2_sp/saml2_config/satosa_frontend.xml
cat backend.xml > ../unicalauth/idp/saml2_config/metadata/satosa_backend.xml
````

## Get SPs and IDPs metadata
for example
````
wget http://sp1.testunical.it:8000/saml2/metadata -O metadata/sp1.xml
wget http://idp1.testunical.it:9000/idp/metadata -O metadata/idp1.xml
````
