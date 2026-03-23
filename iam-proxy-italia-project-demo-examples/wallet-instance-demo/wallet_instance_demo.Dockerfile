# Use iam-proxy-italia as base — opencv, pyeudiw, satosa already installed
FROM ghcr.io/italia/iam-proxy-italia:v3.3.0

RUN apk add --no-cache git ca-certificates && update-ca-certificates

RUN git clone --branch dev https://github.com/italia/iam-proxy-italia-wallet-instance-demo.git /wallet-instance-demo
WORKDIR /wallet-instance-demo

# Install wallet-specific deps into existing venv (pyeudiw/opencv already in base)
# Base image has pyeudiw@2.2.0 (wallet_instance_attestation); wallet dev needs pyeudiw dev (wallet_attestations)
ENV PATH="/.venv/bin:$PATH"
RUN pip install --no-cache-dir "pyeudiw @ git+https://github.com/italia/eudi-wallet-it-python@dev"
RUN pip install --no-cache-dir -e .

# Entrypoint and config generator from iam-proxy demo (not in upstream wallet repo)
COPY iam-proxy-italia-project-demo-examples/wallet-instance-demo/wi_entrypoint.sh /wallet-instance-demo/wi_entrypoint.sh
COPY iam-proxy-italia-project-demo-examples/wallet-instance-demo/generate_wallet_config.py /wallet-instance-demo/scripts/generate_wallet_config.py
RUN chmod +x /wallet-instance-demo/wi_entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/wallet-instance-demo/wi_entrypoint.sh"]
