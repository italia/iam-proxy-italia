## Start Service Provider ##

Syntax: ./start.sh -u URL -p PATH -c

* -u URL is the idp metadata url, is mandatory the presence of an url or the metadata/idp.xml file 
* -p PATH if present, copy the sp metadata on path
* -c clean log, certificates and metadata at end of script

### Example ###
```
$ ./start.sh -u https://idp.example.org/metadata -p /opt/satosa/metadata/sp
```
make new certificates, build a conf with idp metadata from idp.example.org and copy the sp metadata on satosa path

### Files Path ### 
* pki/mykey.pem # sp private key 
* pki/myreq.csr # sp request key
* pki/mycert.pem # sp public key
* metadata/idp.xml # idp metadata
* metadata/sp.xml # sp metadata

### other info ###
* server is run on localhost:9998, for change it edit sp-wsgi/sp_conf.py
* log file is spx.log

