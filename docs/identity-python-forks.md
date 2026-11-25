# PySAML2

````
git clone https://github.com/identitypython/pysaml2
cd pysaml2/

# create current pplnx branch
git remote add ppl nx https://github.com/peppelinux/pysaml2.git
# git checkout --orphan pplnx-v7.5.5
# git reset --hard
# git pull origin master

git checkout -b pplnx-v7.5.5

# pplnx's patches

# https://github.com/IdentityPython/pysaml2/pull/628
# SPID required
git pull pplnx disabled_weak_algs --ff

# https://github.com/IdentityPython/pysaml2/pull/625
# this must be merged at the end, otherwise break the unit tests
git pull pplnx ns_prefixes --ff

# check that tests are ok
python3 -m pytest tests/ -x
````

# SATOSA

iam-proxy-italia depends on upstream SATOSA 8.5.1 from PyPI. The pplnx fork is not used. pyeudiw 2.2.0 accepts `satosa>=8.4,<8.6`, so the dependency stays below 8.6.
