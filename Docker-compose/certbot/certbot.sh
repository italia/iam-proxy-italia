case "$CERT_METHOD" in
  certbot)
    if [[ "$CERTBOT_HOST" == "localhost" || -z "$CERTBOT_HOST" || -z "$CERTBOT_EMAIL" ]]; then
      echo "Invalid CERTBOT configuration"
      exit 1
    fi

    echo "Run CertBot for ${CERTBOT_HOST}"
    certbot certonly --standalone --agree-tos --non-interactive \
      -d "$CERTBOT_HOST" \
      -m "$CERTBOT_EMAIL"
    ;;

  local)
    if [[ -z "$CERTBOT_HOST" ]]; then
      echo "CERTBOT_HOST not set"
      exit 1
    fi

    mkdir -p "/etc/letsencrypt/live/${CERTBOT_HOST}"

    openssl req -x509 -nodes -days 3650 \
      -newkey rsa:3072 \
      -keyout "/etc/letsencrypt/live/${CERTBOT_HOST}/privkey.pem" \
      -out "/etc/letsencrypt/live/${CERTBOT_HOST}/fullchain.pem" \
      -subj "/CN=${CERTBOT_HOST}"
    ;;

  *)
    echo "Manual certificate mode active, no cert generated"
    ;;
esac


