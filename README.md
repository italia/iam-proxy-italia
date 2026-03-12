# IAM Proxy Italia

An **IAM (Identity and Access Management) proxy** is an intermediary that connects identity providers (IdPs) and service providers (SPs) using different protocols. It solves the problem of **interoperability**: legacy or heterogeneous systems (SAML2, OIDC, eID Wallet) cannot communicate directly because they speak different protocols. The proxy translates between them, adapts metadata, and routes requests, so that SPs and RPs do not need to be rewritten to support each identity system.

IAM Proxy Italia is the distribution of the [SATOSA](https://github.com/IdentityPython/SATOSA) IAM Proxy allowing
**SAML-to-SAML**, **OIDC-to-SAML**, **OIDC-to-OIDC**, **SAML-to-Wallet** and **OIDC-to-Wallet** interoperability
with the  **Italian Digital Identity Systems**.

## Table of Contents

1. [Use Cases](#use-cases)
2. [General Architecture of the Solution](#general-architecture-of-the-solution)
3. [Demo Components](#demo-components)
4. [Setup and configuration](#setup-and-configuration)
5. [Authors and Contributors](#authors-and-contributors)

## Use Cases

IAM Proxy Italia supports these main use cases.

### Legacy System implementing new protocols

Legacy SAML2 Service Providers or OIDC RPs authenticate users via:

- SPID, CIE, and eIDAS Identity Providers (metadata and authentication flows adaptation)
- EUDIW Wallet Instance (OpenID4VP)
- IT-Wallet Instance (OpenID4VP)

### Digital Credential Issuance

Users requesting Digital Credentials from Credential Issuers (OpenID4VCI) can be authenticated through:

- Legacy SAML2/OIDC infrastructure (SPID, CIE, eIDAS)
- Credential Presentations (OpenID4VP)

### Credential Issuer using Authentic Sources

Credential Issuers can fetch and enrich credential data from authentic sources using **microservices**: the proxy intercepts requests/responses and calls third-party or local systems to retrieve, validate, or augment attributes before issuing credentials.

<img src="gallery/iam-proxy.svg" width="768">

**Figure1**: *The IAM Proxy Italia acts as a centralized intermediary, providing protocol translation and metadata adaptation between legacy SAML2/OIDC Service Providers and various authentication systems including SPID, CIE, eIDAS Identity Providers, and eID Wallet authentication systems based on OpenID4VP.*

## General Architecture of the Solution

The main components of the IAM Proxy Italia the following ones:

- **Frontend**, SAML2 Identity Provider and or OpenID Connect Provider and or OpenID Wallet Credential Issuer.
- **Backend**, SAML2 Service Provider and or OpenID Connect Relying Party and or OpenID Wallet Relying Party.
- **Microservices**, plugin that may intercept Http Requests or Response to apply rules, do overrides using local data or data provided by a third party remote systems (eg: Authentic Sources). For instance, the **TargetRouting** selects the appropriate Backend to be used with the endpoint (IdP) selected by the user.
- **Discovery Service**, interface that allows users to select the authentication endpoint (which backend to use).

IAM Proxy Italia provides protocol translation and metadata adaptation for Italian Digital Identity systems. Supported **backends** (SP/RP side; connect to IdPs) and **frontends** (IdP/OP side; connect to SPs/RPs):

```mermaid
flowchart LR
  E["Legacy SAML2/OIDC SP/RP"]
  D["IAM Proxy Frontend (IDP/OP)"]
  C["IAM Proxy Core"]
  B["IAM Proxy Backend (SP/RP)"]
  A["Third party authentication services"]
  E --- D --- C --- B --- A
```


### Available Backends

- SAML2 SPID SP
- SAML2 CIE id SP
- SAML2 FICEP SP (eIDAS 1.0)
- SAML2 SP (Satosa native)
- CIE OIDC
- EUDI Wallet (eIDAS 2.0, experimental) OpenID4VP via [eudi-wallet-it-python](https://github.com/italia/eudi-wallet-it-python)

### Available Frontends

- SAML2 IDP (Satosa native)
- OIDC OP via [satosa-oidcop](https://github.com/UniversitaDellaCalabria/SATOSA-oidcop)
- OpenID4VCI via [eudi-wallet-it-python](https://github.com/italia/eudi-wallet-it-python)

## Demo Components

IAM Proxy Italia includes a set of demo components to exercise the features.

User may run them via [Docker Compose](docs/docker-compose.md); use [profiles](docs/docker_compose_profiles.md) to select services. Components live in `iam-proxy-italia-project-demo-examples` and are wired in [Docker-compose/docker-compose.yml](Docker-compose/docker-compose.yml):


| Component                | Path                                         | Docker service         | Profiles                                        | Exercises                                |
| ------------------------ | -------------------------------------------- | ---------------------- | ----------------------------------------------- | ---------------------------------------- |
| **Django SAML2 SP**      | `djangosaml2_sp/`                            | `django_sp`            | demo, dev, saml2                                | SAML2 frontend, SPID/CIE/Wallet backends |
| **Federation authority** | `spid_cie_oidc_django/federation_authority/` | `trust-anchor`         | demo, storage_mongo, oidc                       | OpenID Federation 1.0 Trust Anchor / X.509 PKI certificate authority                         |
| **CIE OIDC provider**    | `spid_cie_oidc_django/provider/`             | `cie-provider`         | demo, storage_mongo, oidc                       | CIE OIDC backend                         |
| **OIDC RP**              | `oidc_rp/`                                   | `relying-party-demo`   | demo, storage_mongo, oidc                       | OIDC frontend (satosa-oidcop)            |
| **MongoDB**              | —                                            | `satosa-mongo`         | demo, storage_mongo, mongoexpress, oidc, wallet | OIDC frontend, CIE OIDC backend, Wallet  |
| **Mongo Express**        | —                                            | `satosa-mongo-express` | demo, mongoexpress                              | MongoDB UI                               |
| **SPID SAML checker**    | —                                            | `spid-samlcheck`       | demo, dev, saml2                                | SPID backend (metadata & flows)          |


See [docs/docker_compose_profiles.md](docs/docker_compose_profiles.md) and [Docker-compose/run-docker-compose.sh](Docker-compose/run-docker-compose.sh).

Tested in CI with [spid-sp-test](https://github.com/italia/spid-sp-test) (metadata, Authn requests, responses).

### Static HTML Pages and Assets

The example project includes preconfigured static pages, including the **Discovery Page Service** for selecting the authentication endpoint. Demo pages are in `iam-proxy-italia-project/static`. Configure redirections in `proxy_conf.yml` and `conf/{backends,frontends}/$filename`. See [docs/gallery.md](docs/gallery.md) for screenshots. 

These demo pages are static files, available in `iam-proxy-italia-project/static`.
To get redirection to these pages, or redirection to third-party services, it is required to configure the files below:

- file: `iam-proxy-italia-project/proxy_conf.yml`, example value: `UNKNOW_ERROR_REDIRECT_PAGE: "https://static-contents.example.org/error_page.html"`
- file: `iam-proxy-italia-project/conf/{backends,frontends}/$filename`, example value: `disco_srv: "https://static-contents.example.org/static/disco.html"`

Other screenshots are available [here](docs/gallery.md).

## Setup and configuration

This project uses [Docker Compose](docs/docker-compose.md); environment variables are documented [here](docs/setup.md#configuration-by-environment-variables).

- **Setup without Docker**: [docs/setup.md](docs/setup.md)
- **Backends and frontends** (config files, enabling modules, Djangosaml2 SP demo): [docs/backends-frontends-configuration.md](docs/backends-frontends-configuration.md)
- **For developers**: [docs/for-developers.md](docs/for-developers.md)
- **External references** (tutorials, SATOSA docs, account linking, related projects): [docs/external-references.md](docs/external-references.md)

## Authors and Contributors

- Giuseppe De Marco
- Andrea Ranaldi and his Team @ ISPRA Ambiente

- Nicola Squartini @ Dipartimento per la trasformazione
- Salvatore Laiso @ E&Y
- Fulvio Scorza and his Team @ Università del Piemonte Orientale
- Paolo Smiraglia (SPID certs)
- Stefano Colagreco @ CNR
- Elisa Nicolussi Paolaz @ Trentino Digitale
- Thomas Chiozzi @ Trentino Digitale
- Identity Python Community (pySAML2 and SATOSA)
- GARR IDEM Community
- Pasquale De Rose @ E&Y
- Sara Longobardi @ Accenture
- Manuel Pacella @ IPZS
- Manuel Ciofo @ IPZS

