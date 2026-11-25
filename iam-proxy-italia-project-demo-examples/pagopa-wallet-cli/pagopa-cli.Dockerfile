# Build from the local wallet-conformance-test checkout (compose additional_contexts: wct).
FROM node:22.19.0-alpine@sha256:d2166de198f26e17e5a442f537754dd616ab069c47cc57b889310a717e0abbf9

WORKDIR /wallet-conformance-test

COPY --from=wct package.json pnpm-lock.yaml ./

RUN npm install -g pnpm@10.23.0 \
    && apk add --no-cache su-exec chromium nss freetype harfbuzz ca-certificates ttf-freefont \
    && adduser -D -h /home/wct -s /bin/sh wct \
    && pnpm install --frozen-lockfile \
    && pnpm rebuild \
    && npm install --prefix /opt/wct-tools mongodb@6.16.0

COPY --from=wct . .

RUN chmod +x ./bin/wct \
    && chmod +x ./docker-entrypoint.sh \
    && mkdir -p ./data \
    && pnpm build \
    && mkdir -p /home/wct/.cache \
    && cp -a /root/.cache/puppeteer /home/wct/.cache/puppeteer \
    && chown -R wct:wct /wallet-conformance-test /home/wct /opt/wct-tools

ENV NODE_PATH=/opt/wct-tools/node_modules
ENV PUPPETEER_CACHE_DIR=/home/wct/.cache/puppeteer
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV CHROME_PATH=/usr/bin/chromium-browser

COPY iam-proxy-italia-project-demo-examples/pagopa-wallet-cli/wct-entrypoint.sh /usr/local/bin/wct-entrypoint.sh
COPY iam-proxy-italia-project-demo-examples/pagopa-wallet-cli/create-presentation-authorize-url.mjs /usr/local/bin/create-presentation-authorize-url.mjs
RUN chmod +x /usr/local/bin/wct-entrypoint.sh \
    && chmod +x /usr/local/bin/create-presentation-authorize-url.mjs

# Run as the non-root wct user. Upstream docker-entrypoint.sh then skips
# su-exec and starts wct directly when the data bind mount is writable.
USER wct

# Upstream docker-entrypoint.sh prepares the data dir and execs wct.
# This wrapper runs issuance and then presentation unless a command is given.
ENTRYPOINT ["wct-entrypoint.sh"]
