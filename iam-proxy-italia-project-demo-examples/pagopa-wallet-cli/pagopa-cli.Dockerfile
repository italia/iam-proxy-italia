FROM ghcr.io/pagopa/wallet-conformance-test:latest

# The published image ships the 1.2.x sources and node_modules, but its
# Dockerfile never runs `pnpm build`. bin/wct imports dist/cli.js, so the
# CLI exits with ERR_MODULE_NOT_FOUND until that build is produced here.
# The upstream entrypoint (docker-entrypoint.sh) is left in place: it
# prepares /wallet-conformance-test/data and execs `./bin/wct`.
USER root
RUN pnpm build \
 && chown -R node:node /wallet-conformance-test
