FROM ghcr.io/pagopa/wallet-conformance-test:latest

# The published image ships the 1.2.x sources and node_modules, but its
# Dockerfile never runs `pnpm build`. bin/wct imports dist/cli.js, so the
# CLI exits with ERR_MODULE_NOT_FOUND until that build is produced here.
# The upstream entrypoint (docker-entrypoint.sh) is left in place: it
# prepares /wallet-conformance-test/data and execs `./bin/wct`.
USER root
COPY iam-proxy-italia-project-demo-examples/pagopa-wallet-cli/wct-entrypoint.sh /usr/local/bin/wct-entrypoint.sh
RUN pnpm build \
 && chmod +x /usr/local/bin/wct-entrypoint.sh \
 && chown -R node:node /wallet-conformance-test

# Upstream docker-entrypoint.sh still prepares the data dir and execs wct.
# This wrapper runs issuance and then presentation unless a command is given.
ENTRYPOINT ["wct-entrypoint.sh"]
