. /djangosaml2_sp/.venv/bin/activate

cd /django_sp

METADATA_URL="https://satosa-nginx/Saml2IDP/metadata"
METADATA_FILE="/django_sp/saml2_sp/saml2_config/satosa-saml2spid.xml"
MAX_TRIES=30
SLEEP=2

for i in $(seq 1 $MAX_TRIES); do
    if wget -q "$METADATA_URL" -O "$METADATA_FILE" --no-check-certificate 2>/dev/null; then
        echo "Satosa IDP Metadata salvato con successo (tentativo $i/$MAX_TRIES)"
        break
    fi
    if [ "$i" -eq "$MAX_TRIES" ]; then
        echo "WARNING: Download Satosa IDP Metadata non riuscito dopo $MAX_TRIES tentativi. Avvio Django comunque; il metadata puo essere copiato dopo."
    else
        echo "Tentativo $i/$MAX_TRIES: Satosa non pronto, riprovo tra ${SLEEP}s..."
        sleep $SLEEP
    fi
done

python -B manage.py migrate
exec python -B manage.py runserver 0.0.0.0:8000