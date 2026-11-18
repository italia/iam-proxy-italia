

TODO

iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] Error while retrieving session by session_id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found. -> in pyeudiw/satosa/backends/openid4vp/endpoints/status_endpoint.py:82-95

iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] invalid_client: ValueError: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found.. client error: no session associated to the state (questo viene da mongo_storage)

- il tasto richiedi nuova credenziale (perché rilevata come scaduta in presentazione) deve fare redirect sulla pagina di emissione

- iam-proxy-italia  | WARNING:pyeudiw.trust.dynamic:No evaluation type found for handler X509Handler (in pyeudiw/trust/dynamic.py:240)

- iam-proxy-italia  | ERROR:pyeudiw.trust.handler.x509:Invalid x509 certificate chain. CRL parsing failed: Connection error: HTTPConnectionPool(host='ca.example.com', port=80): Max retries exceeded with url: /crl.pem (Caused by NameResolutionError("HTTPConnection(host='ca.example.com', port=80): Failed to resolve 'ca.example.com' ([Errno -5] Name has no usable address)")) -> implementare CRL endpoint in spid_cie_oidc_django

- iam-proxy-italia  | [2026-11-12 15:06:20] [ERROR]: Failed to validate TA http://trust-anchor.example.org:5002: HTTP error: 500 -- Internal Server Error [backends.cieoidc.cieoidc._ensure_trust_anchors:301]

- iam-proxy-italia  | [2026-11-12 15:06:20] [ERROR]: Could not resolve trust chain for http://cie-provider.example.org:8002/oidc/op/: No valid Trust Anchors could be loaded. [backends.cieoidc.cieoidc._generate_trust_chains:238]

 - iam-proxy-italia  | /.venv/lib/python3.12/site-packages/idpyoidc/time_util.py:30: SyntaxWarning: invalid escape sequence '\d'
iam-proxy-italia  |   TIME_FORMAT_WITH_FRAGMENT = re.compile("^(\d{4,4}-\d{2,2}-\d{2,2}T\d{2,2}:\d{2,2}:\d{2,2})\.\d*Z$")

- Non riesco a inviare i dati: Exception :Errore ritornato dall'endpoint https://iam-proxy-italia.example.org/OpenID4VP/request-uri?client_id=openid_federation%3Ahttps%3A%2F%2Fiam-proxy-italia.example.org%2FOpenID4VP&request_uri=https%3A%2F%2Fiam-proxy-italia.example.org%2FOpenID4VP%2Frequest-uri&request_uri_method=get&state=fde82b77-cd62-4c0e-a7b3-1b25dd94715a: invalid_request - request error: request object already issued (HTTP Status code: 400). -> investigare, consentirlo