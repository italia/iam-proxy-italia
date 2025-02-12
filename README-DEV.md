## SPID technical Requirements

The SaToSa **SPID** backend contained in this project uses specialized forks of pySAML2 and SATOSA, that implements the following patches,
read [this](README.idpy.forks.mngmnt.md) for any further explaination about how to patch by hands.

All the patches and features are currently merged and available with the following releases:

- [pysaml2](https://github.com/peppelinux/pysaml2/tree/pplnx-v7.0.1-1)
- [SATOSA](https://github.com/peppelinux/SATOSA/tree/oidcop-v8.0.0)

## Pending contributions to idpy

These are mandatory only for getting Spid SAML2 working, these are not needed for any other traditional SAML2 deployment:

- [disabled_weak_algs](https://github.com/IdentityPython/pysaml2/pull/628)
- [ns_prefixes](https://github.com/IdentityPython/pysaml2/pull/625)
- [SATOSA unknow error handling](https://github.com/IdentityPython/SATOSA/pull/324)
- [SATOSA redirect page on error](https://github.com/IdentityPython/SATOSA/pull/325)
