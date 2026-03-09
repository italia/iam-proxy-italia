case "$CERT_METHOD" in
  certbot)
    if [[ "$HOSTNAME" == "localhost" || -z "$HOSTNAME" || -z "$CERTBOT_EMAIL" ]]; then
      echo "Invalid CERTBOT configuration"
      exit 1
    fi

    echo "Run CertBot for ${HOSTNAME}"
    certbot certonly --standalone --agree-tos --non-interactive \
      -d "$HOSTNAME" \
      -m "$CERTBOT_EMAIL"
    ;;

  local)
    if [[ -z "$HOSTNAME" ]]; then
      echo "HOSTNAME not set"
      exit 1
    fi

    mkdir -p "/etc/letsencrypt/live/${HOSTNAME}"

    openssl req -x509 -nodes -days ${CERTBOT_DAYS} \
      -newkey ${CERTBOT_KTY} \
      -keyout "/etc/letsencrypt/live/${HOSTNAME}/privkey.pem" \
      -out "/etc/letsencrypt/live/${HOSTNAME}/fullchain.pem" \
      -subj "/CN=${HOSTNAME}"
    ;;

  *)
    echo "Manual certificate mode active, no cert generated"
    ;;
esac


