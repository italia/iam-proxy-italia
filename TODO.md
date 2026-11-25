## TODO

iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] Error while retrieving session by session_id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found. -> in pyeudiw/satosa/backends/openid4vp/endpoints/status_endpoint.py:82-95

iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] invalid_client: ValueError: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found.. client error: no session associated to the state (questo viene da mongo_storage)

- iam-proxy-italia  | WARNING:pyeudiw.trust.dynamic:No evaluation type found for handler X509Handler (in pyeudiw/trust/dynamic.py:240)

- iam-proxy-italia  | ERROR:pyeudiw.trust.handler.x509:Invalid x509 certificate chain. CRL parsing failed: Connection error: HTTPConnectionPool(host='ca.example.com', port=80): Max retries exceeded with url: /crl.pem (Caused by NameResolutionError("HTTPConnection(host='ca.example.com', port=80): Failed to resolve 'ca.example.com' ([Errno -5] Name has no usable address)")) -> implementare CRL endpoint in spid_cie_oidc_django

 - iam-proxy-italia  | /.venv/lib/python3.12/site-packages/idpyoidc/time_util.py:30: SyntaxWarning: invalid escape sequence '\d'
iam-proxy-italia  |   TIME_FORMAT_WITH_FRAGMENT = re.compile("^(\d{4,4}-\d{2,2}-\d{2,2}T\d{2,2}:\d{2,2}:\d{2,2})\.\d*Z$")