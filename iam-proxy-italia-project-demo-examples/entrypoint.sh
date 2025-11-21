. /djangosaml2_sp/.venv/bin/activate

METADATA_URL="https://satosa-nginx/Saml2IDP/metadata"
wget $METADATA_URL -O /django_sp/saml2_sp/saml2_config/satosa-saml2spid.xml --no-check-certificate

if [ $? -eq 0 ]; then
    echo "Satosa IDP Metadata salvato con successo"
else
    echo "ERRORE: Download Satosa IDP Metadata fallito!."
fi

python -B manage.py migrate
python -B manage.py runserver 0.0.0.0:8000