# X.509 chain generator for pyeudiw (gen_x509_chain_iam_proxy.py)

The script `scripts/gen_x509_chain_iam_proxy.py` generates a root CA, intermediate CA, and leaf certificate chain in PEM form for use in pyeudiw trust configuration (OpenID4VP backend and OpenID4VCI frontend). The **leaf certificate** is issued for a configurable FQDN and for the same key as `metadata_jwks[0]` in the target YAML, so the trust layer can validate the chain.

## Requirements

- Python 3 with `cryptography` and `pyeudiw` (e.g. from [eudi-wallet-it-python](https://github.com/italia/eudi-wallet-it-python)).
- Run from the **iam-proxy-italia** repo root (or set `PYTHONPATH` to include the path to `eudi-wallet-it-python` so `pyeudiw.x509.chain_builder` can be imported).

## Usage

```bash
# From iam-proxy-italia repo root
PYTHONPATH=/path/to/eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py [OPTIONS]
```

| Option        | Description |
|---------------|-------------|
| `--frontend`  | Use the OpenID4VCI frontend key (`openid4vci_frontend.yaml` `metadata_jwks[0]`) for the leaf certificate. Use this when updating `conf/frontends/openid4vci_frontend.yaml` trust.x509. |
| `--fqdn NAME` | Set the leaf certificate FQDN (Subject CN and SAN DNS) to `NAME`. Overrides `SATOSA_HOSTNAME` and the default. |
| `--ca-only`   | Print only the root CA PEM (for `certificate_authorities`). |
| `--chain`     | Print only the three PEMs (leaf, intermediate, root), one block each. |

If neither `--fqdn` nor `SATOSA_HOSTNAME` is set, the leaf FQDN defaults to `iam-proxy-italia.example.org`.

## Custom FQDN for demo purposes

For demos (e.g. local or custom domain), you can set the leaf FQDN in two ways:

1. **Environment variable**  
   Set `SATOSA_HOSTNAME` to your demo hostname, then run the script:

   ```bash
   export SATOSA_HOSTNAME=my-demo.example.com
   PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py --frontend
   ```

2. **Command-line option**  
   Pass the FQDN explicitly with `--fqdn`:

   ```bash
   PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py --frontend --fqdn my-demo.example.com
   ```

Then:

- Paste the printed **CA** into `certificate_authorities` in your backend or frontend YAML.
- Paste the three cert blocks (leaf, intermediate, root) into `leaf_certificate_chains_by_ca` under the same CA key (e.g. `ca.example.com`).
- Set **client_id** (backend) or **issuer_id** (frontend) to `x509_san_dns:<your-leaf-fqdn>`, e.g. `x509_san_dns:my-demo.example.com`.

The leaf certificate will have Subject CN and SAN DNS equal to the FQDN you used; the trust handler expects `client_id`/`issuer_id` to match that value.

## Examples

**Backend chain (pyeudiw_backend.yaml), default FQDN**

```bash
PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py
```

**Frontend chain (openid4vci_frontend.yaml), default FQDN**

```bash
PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py --frontend
```

**Frontend chain with custom demo FQDN**

```bash
PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py --frontend --fqdn demo.myorg.local
```

**Only refresh the root CA PEM**

```bash
PYTHONPATH=../eudi-wallet-it-python python3 scripts/gen_x509_chain_iam_proxy.py --ca-only
```

## Where to put the output

- **Backend** (`conf/backends/pyeudiw_backend.yaml`): under `trust.x509.config` → `certificate_authorities` and `leaf_certificate_chains_by_ca`. Set `client_id` to `x509_san_dns:<leaf-fqdn>` (or use `!ENV PYEUDIW_X509_CLIENT_ID` with that value in the environment).
- **Frontend** (`conf/frontends/openid4vci_frontend.yaml`): under `config.trust.x509.config` → same keys. Set `issuer_id` to `x509_san_dns:<leaf-fqdn>`.

The leaf certificate **must** be issued for the same key as the first key in `metadata_jwks` in that same file. Use `--frontend` for the frontend config and no `--frontend` for the backend (each has its own `metadata_jwks[0]`).
