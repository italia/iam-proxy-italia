if [[ "$CERTBOT_ENABLED" == "true" && "${CERTBOT_HOST}" != "localhost" && -n "${CERTBOT_HOST}" && -n "${CERTBOT_EMAIL}" ]]; then
  echo "Run CertBot for ${CERTBOT_HOST}"
  certbot certonly --standalone --agree-tos --non-interactive -d ${CERTBOT_HOST} -m ${CERTBOT_EMAIL}

#    mkdir -p /etc/letsencrypt/live/$CERTBOT_HOST
#
#  openssl req -x509 -nodes -days 365 \
#    -newkey rsa:2048 \
#    -keyout /etc/letsencrypt/live/$CERTBOT_HOST/privkey.pem \
#    -out /etc/letsencrypt/live/$CERTBOT_HOST/fullchain.pem \
#    -subj "/CN=$CERTBOT_HOST"

else
  echo "CertBot skipped"
fi
exit 0
