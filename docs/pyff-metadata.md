pyFF
----
[python Federation Feeder](http://pyff.io/)
[github](https://github.com/IdentityPython/pyFF)

pyFF is a omnicomprensive advanced Metadata appliance.
It download, validate, aggregate, export one or many entities in xml format, in json format, as a querable [MDX service](https://datatracker.ietf.org/doc/draft-young-md-query-saml/), it will also give us a [DiscoveryService](http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-idp-discovery.pdf) and a user friendly web catalog with statistics and all the usefull informations as well, with an agile search engine... The first time I used it I wondered what I had done until then.

Please also rememeber that "MDX" is an acronym for MetaData eXchange and refers to a more general concept of which the "MDQ", acronym for Metadata Query Protocol, is just one component.

## Installation
````
pip install git+https://github.com/IdentityPython/pyFF.git
````

## First run

The following command will print in stdout all the pyFF's execution log, if you want to put it in a file just add `--log=pyff.log` after `--loglevel`.

Run as batch (recommended!)

````
pyff  pipelines/spid_idp.fd
````

This command will run a MDX server instance, see `main()` in `pyff.mdx`
````
pyffd -p pyff.pid -f -a --loglevel=DEBUG --error-log=error.log --access-log=access.log --dir=`pwd` -H 0.0.0.0 -P 8001 --frequency=180 --no-caching pipelines/md.fd
````

When it complete the downloads of all the metadata then exposes all the SAML entities in a _human navigable_ web catalog, this will permit us to test the DiscoveryService and see common stats.

Useful things that we need to know
1. pyFF uses by default a local sqllite db, it's automatically created in the working directory on run.


## how does it work
You need also to read:
- https://pythonhosted.org/pyFF/
- https://github.com/IdentityPython/pyFF

pyFF works with configuration files called _pipelines_, it exposes services and all its features depending of what we configure in those _pipelines_ files. The following example is used to validate and download to `./garr` folder all the configured metadata, then aggregate them in a sqllite database as a cache for better I/O performance.

`custom_examples/` contains some of the following examples.

*garr.xrd*
````
<?xml version="1.0"?>
<XRDS xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="http://md.idem.garr.it/metadata/idem-test-metadata-sha256.xml"/>
  </XRD>
  <XRD>
    <Link rel="urn:oasis:names:tc:SAML:2.0:metadata" href="http://md.idem.garr.it/metadata/idem-metadata-sha256.xml"/>
  </XRD>
</XRDS>
````

*garr.fd*
````
# load) download SAML Metadatas configured in these files
- load xrd ./garr-loaded.xrd:
  - custom_examples/garr.xrd

# select) this could, or not, specify a selection filter for EntityDescriptors in the metadata repository.
# it could be a XPATH selection to get for example only the IDP as: "http://mds.edugain.org!//md:EntityDescriptor[md:IDPSSODescriptor]"
# in this case it will take all of them
- select

# the folder where single entities will be stored
- store:
     directory: ./garr

# publish) causes the active document to be stored in an XML file.
- publish:
     output: ./garr-loaded.xml

# stats) prints out some information about the metadata repository.
- stats

# MDX server, see: https://pythonhosted.org/pyFF/examples.html#example-5-mdx
- when request:
    - select
    - pipe:
        - when accept application/xml:
             - xslt:
                 stylesheet: tidy.xsl
             - first
             - finalize:
                cacheDuration: PT5H
                validUntil: P10D
             - sign:
                 key: sign.key
                 cert: sign.crt
             - emit application/xml
             - break
        - when accept application/json:
             - xslt:
                 stylesheet: discojson.xsl
             - emit application/json:
             - break
````

## DS and MDQ Web resources

These for example will let us understand how the things works, easily.
````
# get all the entitities in a single aggregated metadata
/entities

# get a single metadata, related to the hashed entityID in the request URL
# the encoded value is a hashed entity_id
/entities/{sha1}baf9ddc66fa9d6a6077e72cd04e0e292ccbc7676

# access to the DiscoveryService web resource, we have two arguments
# entityID, is the identifier of the calling SP, the SP that requests to use the DS
# return, is the SP resource where to return the selected entityID of the user
/role/idp.ds?entityID=https%3A%2F%2Fsatosa.testunical.it%2FSaml2%2Fmetadata&return=https%3A%2F%2Fsatosa.testunical.it%2FSaml2%2Fdisco

# when the user selects an IDP to authenticate to, JS will forge a call using the previous "return" url
# more the entityID argument, containing the selected IDP
/Saml2/disco?entityID=https://idp1.testunical.it/idp/metadata

# these will fetch all the IDP or the SP in json format, like
# [{"entityID": "https://idp1.testunical.it/idp/metadata","type": "idp","title": "IDP testunical","icon": "https://idp1.testunical.it/static/img/logo.svg","descr": "IDP testunical","auth": "saml"}, ... ]
/role/idp.json
/role/sp.json

# same as the previous but in XML format
/role/sp.xml
/role/idp.xml
````

## Production

The best implementation would be a pure httpd static serve, see `production_setup/` examples.
Otherwise you can use a real MDQ/X server like the followings

- pyffd (discouraged)
- [Django-MDQ](https://developers.italia.it/it/software/unical-universitadellacalabria-django-mdq.html)
- [mdq-server](https://github.com/iay/mdq-server)


## Playing MDX service

````
import io
import json
import urllib.request

from saml2.mdstore import MetaDataMDX

# when available
# mdq_url = "http://demo2.aai-test.garr.it:8080"
# mdq_cert = "http://demo2.aai-test.garr.it/idem-mdq-pilot-cert.pem"

mdq_url = "http://mdx.eduid.hu/"
mdq_cert = "http://metadata.eduid.hu/current/mdx-test-signer-2015.crt"
entity2check = 'https://idp.unical.it/idp/shibboleth'

cert = io.BytesIO()
cert.write(urllib.request.urlopen(mdq_cert).read())
cert.seek(0)

mdx = MetaDataMDX(mdq_url, cert=cert)

# a preview, from this we get all the services to query
print(mdx.dumps())

eid_tree = json.loads(mdx.dumps())
#
eid_tree[0][1].keys()

# EC
# mdx.entity_categories(entity2check)

# certificati
mdx.certs(entity2check, "idpsso", use="encryption")

# get certs from idp
mdx.service(entity2check, 'idpsso_descriptor', 'single_sign_on_service')
mdx.certs(entity2check, "idpsso", use="signing")

# servizi di un sp
mdx.service("https://that.sp.entity.id", "idpsso_descriptor", "services")
mdx.certs(entity2check, "spsso", use="signing")
````


## Fancy screenshot (what you will get)

When it start the only content available on its embedded webserver is a loading WebPage, this will persist until the metadata download and validation finishes, this will be also the only thing you will see if metadata could not be imported (404 on their page).


![Loading](gallery/service_request.png)
**Frontend**: Loading page during metadata importing procedure.


![Home](gallery/Selezione_537.png)
**Home page**: All the entitities are now classified by categories, they could be also selected with an agile search engine. All the metadata information are now available. pyFF also exposes the pipelines used, the command used to start the server, in other words _everything_.

Additional resources
--------------------

- [pyFF Roadmap](https://github.com/IdentityPython/pyFF/wiki/Roadmap)
- Using MDX with pySAML2, [read source](https://github.com/IdentityPython/pysaml2/blob/master/src/saml2/mdstore.py#L781)
- [Metadata Query Protocol](https://github.com/iay/md-query)
- pySAML2 MDQ usage, see:
  - https://github.com/IdentityPython/pysaml2/blob/master/docs/howto/config.rst#metadata
  - https://github.com/IdentityPython/pysaml2/issues/410
  - https://github.com/IdentityPython/pysaml2/issues/586
  -
