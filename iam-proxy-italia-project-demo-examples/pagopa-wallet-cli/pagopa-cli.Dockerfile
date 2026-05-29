FROM ghcr.io/pagopa/wallet-conformance-test:latest

COPY iam-proxy-italia-project-demo-examples/pagopa-wallet-cli/pagopa-entrypoint.sh /usr/local/bin/
COPY iam-proxy-italia-project-demo-examples/pagopa-wallet-cli/config/ /wallet-conformance-test/

RUN chmod +x /usr/local/bin/pagopa-entrypoint.sh

ENTRYPOINT ["pagopa-entrypoint.sh"]
