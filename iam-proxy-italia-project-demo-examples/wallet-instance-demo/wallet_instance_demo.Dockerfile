# Use iam-proxy-italia as base — opencv, pyeudiw, satosa already installed
FROM ghcr.io/italia/iam-proxy-italia:v3.3

RUN apk add --no-cache git

RUN git clone --branch dev https://github.com/italia/iam-proxy-italia-wallet-instance-demo.git /wallet-instance-demo
WORKDIR /wallet-instance-demo

# Install wallet-specific deps into existing venv (pyeudiw/opencv already in base)
# Base image has pyeudiw@2.2.0 (wallet_instance_attestation); wallet dev needs pyeudiw dev (wallet_attestations)
ENV PATH="/.venv/bin:$PATH"
RUN pip install --no-cache-dir "pyeudiw @ git+https://github.com/italia/eudi-wallet-it-python@dev"
RUN pip install --no-cache-dir -e .

COPY iam-proxy-italia-project-demo-examples/wallet-instance-demo/wi_entrypoint.sh /wallet-instance-demo/wi_entrypoint.sh
RUN chmod +x /wallet-instance-demo/wi_entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/wallet-instance-demo/wi_entrypoint.sh"]
