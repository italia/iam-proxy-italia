import copy
import os
import sys

sys.path.append(os.getcwd())

from djangosaml2_sp.sp_pysaml2_shibidp import (SAML_CONFIG,
                                               BASE_URL,
                                               BASE_DIR,
                                               IDP_URL)

from pprint import pprint

from saml2.config import SPConfig
from saml2.response import AuthnResponse
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.client import Saml2Client


# OutStanding Queries
# outstanding = {'id-R3qGBIK1FKbybkEOo': '/', 'id-vV5JVaBZCuC2LHP9Y': '/', 'id-TH9lfrLJL4KtNuEZJ': '/', 'id-KeYf8iMkonCWaqGrd': '/', 'id-S8lzm7lkEYIwokDVZ': '/', 'id-1naCBqIuGqm31mFnC': '/', 'id-D5bhbXLDxt6nS2QtZ': '/', 'id-UCjbQ7AS1nGG5wSN5': '/', 'id-EdrCM5hBIDix23Bf5': '/', 'id-p3yvaSmx6TJPZ0qK7': '/', 'id-DgwqMaGwOJYRxnzQe': '/'} 

outstanding = None
outstanding_certs = None
conv_info = None

conf = SPConfig()

conf.load(copy.deepcopy(SAML_CONFIG))
client = Saml2Client(conf)

# client arguments
selected_idp = None
came_from = '/'
# conf['sp']['authn_requests_signed'] determines if saml2.BINDING_HTTP_POST or saml2.BINDING_HTTP_REDIRECT
binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' # saml2.BINDING_HTTP_REDIRECT
sign=False
sigalg=None
nsprefix = {'ds': 'http://www.w3.org/2000/09/xmldsig#', 'md': 'urn:oasis:names:tc:SAML:2.0:metadata', 'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol', 'xenc': 'http://www.w3.org/2001/04/xmlenc#', 'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}

# craft SAML Request
session_id, result = client.prepare_for_authenticate(
                                                     entityid=selected_idp,
                                                     relay_state=came_from,
                                                     binding=binding,
                                                     sign=sign,
                                                     sigalg=sigalg,
                                                     nsprefix=nsprefix
                                                     )

target = result.get('headers')[0][1]

# browser init
import requests

r = requests.Session()
# SAMLRequest is in target URL
sp_saml_request = r.get(target, verify=False)
if not sp_saml_request.ok: raise ('SP SAML Request Failed')


# fetch post ACTION url from form then POST
import re
action_post_regexp ='(?P<name>action)="(?P<value>[a-zA-Z0-9\.\:\/\_\?\=]*)"'
s = re.search(action_post_regexp, sp_saml_request.text)
if not s: raise ('IDP Login POST doesn\'t returns correctly')

post_target = target.split('?')[0]+'?'+s.groupdict()['value'].split('?')[1]

payload = {
'j_username': 'mario',
'j_password': 'cimpa12',
'donotcache': 1,
'_shib_idp_revokeConsent': True,
'_eventId_proceed': ''
}

# post target is in one of the but we already fetched it in the previous FORM.
# IDP supports all those defined in its Metadata
# <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://idp.testunical.it/idp/profile/Shibboleth/SSO"/>
# <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.testunical.it/idp/profile/SAML2/POST/SSO"/>
# <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://idp.testunical.it/idp/profile/SAML2/POST-SimpleSign/SSO"/>
# <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.testunical.it/idp/profile/SAML2/Redirect/SSO"/>

idp_login_response = r.post(post_target, data=payload, verify=False)
if not idp_login_response.ok: raise ('IDP Login response Failed')

# Response
# extract SAML2 authn response from IDP response
saml2_response_regexp ='name="(?P<name>SAMLResponse)" value="(?P<value>[a-zA-Z0-9\.\:\/\_\?\=\+\-]*)"'
sr = re.search(saml2_response_regexp, idp_login_response.text)
if not sr:
    print(idp_login_response.text)
    raise ('IDP Response doesn\'t contain a valid SAML value')


# Decode SAML2 base64 String
import base64

saml_auth_response_b64 = sr.groupdict().get('value')
saml_auth_response = base64.b64decode(saml_auth_response_b64)
xmlstr = saml_auth_response.decode('ascii')

# Fancy SAML print
# from lxml import etree
# root = etree.XML(xmlstr.encode('ascii'))
# print(etree.tostring(root, pretty_print=True).decode('utf-8'))

# pySAML2 parse authn response (sign and decrypt features included)

kwargs = {
            "outstanding_queries": outstanding,
            "outstanding_certs": outstanding_certs,
            "allow_unsolicited": conf._sp_allow_unsolicited,
            "want_assertions_signed": conf._sp_want_assertions_signed,
            "want_response_signed": conf._sp_want_response_signed,
            "return_addrs": conf.endpoint("assertion_consumer_service", binding, "sp"),
            "entity_id": conf.entityid,
            "attribute_converters": conf.attribute_converters,
            "allow_unknown_attributes": conf.allow_unknown_attributes,
            'conv_info': conv_info
            }

# xml unravel fails bacause of b64 inflate method
# pr = client.parse_authn_request_response(saml_auth_response_b64,
                                     # binding,
                                     # outstanding=outstanding,
                                     # outstanding_certs=None,
                                     # conv_info=None)

authn_response = AuthnResponse(client.sec, **kwargs)

# response.loads(xmlstr, False, origxml=origxml)
# authn_response.loads(xmlstr, False, origxml=xmlstr)

# response.py -> AuthnResponse
# in response.loads -> ._loads ->
# authn_response.signature_check(xmldata, origdoc=origxml, must=self.require_signature,
# require_response_signature=self.require_response_signature,
# **args)

# HERE err=18;msg=self signed certificate !
#samlp_response = authn_response.signature_check(xmlstr, must=0, require_response_signature=0)

# ea = samlp_response.encrypted_assertion[0]
# ea.encrypted_data.cipher_data.cipher_value.text

# consulta python-xmlsec
# https://github.com/mehcode/python-xmlsec/issues/22

from lxml import etree
import xmlsec

xmlsec.enable_debug_trace(True)
km = xmlsec.KeysManager()

km.add_key(xmlsec.Key.from_file(conf.key_file,
                                xmlsec.KeyFormat.PEM))
enc_ctx = xmlsec.EncryptionContext(km)

# root = etree.parse("response.xml").getroot()
root = etree.XML(xmlstr.encode('ascii'))
node = root.xpath(
    "//enc:EncryptedData",
    namespaces={'enc': 'http://www.w3.org/2001/04/xmlenc#'},
)
enc_data = node[0]

print()
print(etree.tostring(enc_data))
print()
decrypted = enc_ctx.decrypt(enc_data)

print()
print(etree.tostring(decrypted))
