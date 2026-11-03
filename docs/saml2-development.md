## SPID technical Requirements

The SaToSa **SPID** backend contained in this project uses a specialized fork of pySAML2. SATOSA comes from the upstream release. Read [identity-python-forks.md](identity-python-forks.md) for how the pySAML2 patches are applied.

The releases in use are:

- [pysaml2](https://github.com/peppelinux/pysaml2/tree/pplnx-v7.5.5)
- [SATOSA 8.5.1](https://github.com/IdentityPython/SATOSA/releases/tag/v8.5.1)

## Pending contributions to idpy

These are mandatory only for getting Spid SAML2 working, these are not needed for any other traditional SAML2 deployment:

- [disabled_weak_algs](https://github.com/IdentityPython/pysaml2/pull/628)
- [ns_prefixes](https://github.com/IdentityPython/pysaml2/pull/625)

## Recommendations

- **Discovery Service**: You must enable more than a single IdP (multiple metadata or single metadata with multiple entities) to get *Discovery Service* working.

- **Single Logout (SLO)**: SATOSA now supports SLO. Previously, the spidSaml2 backend was configured with `Authnforce -> True` as a workaround. For further information see [Single Logout in Satosa](https://github.com/IdentityPython/SATOSA/issues/211).

- **Policy section**: SATOSA Saml2 backend configuration has a **policy** section that lets you define specialized behaviours and configuration for each SP (each by entityid). In the example project a single "default" behaviour is defined with attributes **name_format** set to **urn:oasis:names:tc:SAML:2.0:attrname-format:uri**, useful when handling many service providers for which a static definition per SP would be cumbersome.

- **Attribute mapping**: A hybrid mapping in `iam-proxy-italia-project/attributes-maps/satosa_spid_uri_hybrid.py` supports both *URI* and *BASIC* formats. You can customize or decouple these formats in different files and per SP.
