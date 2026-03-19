FROM python:3.13-alpine

RUN apk add --no-cache \
    bash \
    git \
    ca-certificates \
    gcc \
    g++ \
    musl-dev \
    linux-headers \
    python3-dev \
    cmake \
    make \
    ninja \
    dos2unix \
    ffmpeg \
    && update-ca-certificates

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN git config --global http.sslVerify false

RUN git clone https://github.com/italia/iam-proxy-italia-wallet-instance-demo.git

WORKDIR /iam-proxy-italia-wallet-instance-demo

RUN git checkout dev

RUN mkdir "config"

RUN cp config.json.example config/config.json

RUN chmod +x wi_demo_entrypoint.sh

ENTRYPOINT ["./wi_demo_entrypoint.sh"]
