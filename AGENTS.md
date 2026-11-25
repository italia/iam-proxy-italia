# IAM Proxy Italia agent instructions

This repository deploys the Italian IT-Wallet with SATOSA: OpenID4VCI issuance, OpenID4VP presentation, and SPID/CIE. The normative text is the IT-Wallet Technical Specifications. Editorial rules of that Sphinx repository apply only when editing that repository.

## Where content lives

- Issuer and verifier configuration: `iam-proxy-italia-project/conf/`. Docker mounts a second copy at `Docker-compose/iam-proxy-italia-project/conf/`. A metadata change belongs in both copies.
- Compose and startup: `Docker-compose/`. `run-docker-compose.sh` without `-s` removes containers and images and pulls public tags before `up`. `-f` only deletes local data directories.
- pyeudiw is the commit pinned in `pyproject.toml` and `poetry.lock`. Editing the local `eudi-wallet-it-python` checkout does not change the running issuer until that commit is the pin and the image is rebuilt, or the changed file is copied into the container.
- The wallet instance demo is the separate repository `iam-proxy-italia-wallet-instance-demo`.

## Specification

Implement the behavior the specification states. Do not copy the same requirement into a second module. Point to the function that owns it.

Do not weaken or strengthen a specified behavior unless the user asks. When the user asks for a divergence, keep that divergence explicit in the change.

Revocation is the Status List (`GET`, `application/statuslist+jwt`). Do not reintroduce the status assertion.

Example hostnames stay under `example.org` (`iam-proxy-italia.example.org`, `demo-wi.example.org`). Do not put production URLs in examples or default configuration.

## Git and images

Do not create a commit, and do not push, unless the user asks for that in the current request. Do not publish or rebuild the image unless asked.

## Editing

Change only the requested part. Do not rewrite neighboring code for style.

One sentence states one outcome. Do not join clauses with a semicolon.
