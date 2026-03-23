# Stage 1 – build: install npm deps and generate bootstrap-italia assets
FROM node:22-alpine AS build
WORKDIR /build

# Separate package files for better layer caching
COPY package*.json ./
RUN npm ci --ignore-scripts

# Copy the rest of the source, then generate assets
COPY . .
RUN npm run update-bootstrap-italia


# Stage 2 – serve: lightweight static-web-server (Alpine)
FROM joseluisq/static-web-server:2-alpine

# Copy only the assets that must be served.
# Files land under /public/static/ so the server naturally handles
# requests with the /static prefix without any path-rewrite in the ingress.
COPY --from=build /build/bootstrap-italia /public/static/bootstrap-italia
COPY --from=build /build/cie             /public/static/cie
COPY --from=build /build/css             /public/static/css
COPY --from=build /build/idem            /public/static/idem
COPY --from=build /build/img             /public/static/img
COPY --from=build /build/js              /public/static/js
COPY --from=build /build/locales         /public/static/locales
COPY --from=build /build/spid            /public/static/spid
COPY --from=build /build/svg             /public/static/svg
COPY --from=build /build/wallet-it       /public/static/wallet-it
COPY --from=build /build/disco.html      /public/static/disco.html
COPY --from=build /build/error_page.html /public/static/error_page.html

ENV SERVER_PORT=8000
ENV SERVER_ROOT=/public
