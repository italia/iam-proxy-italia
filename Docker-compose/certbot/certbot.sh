if [[ "$CERTBOT_ENABLED" == "true" && "${CERTBOT_HOST}" != "localhost" && -n "${CERTBOT_HOST}" && -n "${CERTBOT_EMAIL}" ]]; then
  echo "Run CertBot for ${CERTBOT_HOST}"
  certbot certonly --standalone --agree-tos --non-interactive -d ${CERTBOT_HOST} -m ${CERTBOT_EMAIL}
else
  echo "CertBot skipped"
fi
exit 0
