

TODO

iam-proxy-italia  | /.venv/lib/python3.12/site-packages/urllib3/connectionpool.py:1129: InsecureRequestWarning: Unverified HTTPS request is being made to host 'demo-wi.example.org'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
iam-proxy-italia  |   warnings.warn(
iam-proxy-italia  | WARNING:pyeudiw.trust.dynamic:No evaluation type found for handler X509Handler
iam-proxy-italia  | /.venv/lib/python3.12/site-packages/urllib3/connectionpool.py:1129: InsecureRequestWarning: Unverified HTTPS request is being made to host 'iam-proxy-italia.example.org'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
iam-proxy-italia  |   warnings.warn(
iam-proxy-italia  | [pid: 98|app: 0|req: 54/534] 172.18.0.7 () {50 vars in 709 bytes} [Wed Nov 11 17:07:07 2026] GET /OpenID4VCI/.well-known/openid-federation => generated 24982 bytes in 73 msecs (HTTP/1.1 200) 3 headers in 875 bytes (1 switches on core 0)
iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] Error while retrieving session by session_id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found.
iam-proxy-italia  | ERROR:pyeudiw.tools.base_logger:[urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57] invalid_client: ValueError: Document with session id urn:uuid:971ac49d-b048-4980-a60c-6271aea6ae57 not found.. client error: no session associated to the state
iam-proxy-italia  | [pid: 100|app: 0|req: 134/535] 172.18.0.1 () {68 vars in 1203 bytes} [Wed Nov 11 17:07:07 2026] GET /OpenID4VP/status => generated 100 bytes in 94 msecs (HTTP/1.1 401) 3 headers in 865 bytes (1 switches on core 0)
iam-proxy-italia  | _config = {'verify': False, 'timeout': 4}
iam-proxy-italia  | ERROR:pyeudiw.trust.handler.x509:Invalid x509 certificate chain. CRL parsing failed: Connection error: HTTPConnectionPool(host='ca.example.com', port=80): Max retries exceeded with url: /crl.pem (Caused by NameResolutionError("HTTPConnection(host='ca.example.com', port=80): Failed to resolve 'ca.example.com' ([Errno -5] Name has no usable address)"))


- il tasto richiedi nuova credenziale (perché rilevata come scaduta in presentazione) deve fare redirect sulla pagina di emissione
- quando accedi alla sezione attestati ottenuti, rileva gli attestati scaduti e marcali come tali. Nel menu a sinistra aggiungi l'icona del triangolo di warning
- il parametro di config del nonce_duration è stato riposizionato, prima era coem se dovesse stare nella root del config. Rilevare tutti gli altri parametri che dvrebbero stare in un contesto specifico piuttosto che nella root
- ✅ @run-docker-compose.sh: -h flag implemented (shows help and exits with 0)