# IAM Proxy Italia - OpenID4VP/OpenID4VCI Flow Analysis

## Executive Summary

Il wallet tenta di effettuare richieste a endpoint `.well-known` che non sono configurati correttamente nel proxy SATOSA. Questi endpoint vengono richiesti dai trust handler (DirectTrustJar, DirectTrustSdJwtVc) durante la verifica della fiducia negli emittenti/verifier.

## Errori Riscontrati

### 1. `.well-known/jwt-vc-issuer/OpenID4VCI`
**Log Error:**
```
[2026-11-12 16:01:40] [ERROR]: [urn:uuid:8e9cd267-4a87-4407-9e1b-942390ee2bc3]
'message': 'URL-path is not bound to any endpoint function'
'error': "'.well-known/jwt-vc-issuer/OpenID4VCI' not bound to any function"
```

**Causa:** Il frontend OpenID4VCI non è registrato nella configurazione SATOSA.

**Path richiesto:**
- `.well-known/jwt-vc-issuer/OpenID4VCI`

**Source codice (pyeudiw):**
- `pyeudiw/trust/handler/direct_trust_sd_jwt_vc.py:9` - DEFAULT: `/.well-known/jwt-vc-issuer`

### 2. `OpenID4VP/.well-known/jar-issuer`
**Log Error:**
```
[2026-11-12 20:11:11] [ERROR]: [urn:uuid:44f67cf7-14c1-4f36-a1da-ea243dd36433]
'message': 'URL-path is not bound to any endpoint function'
'error': "'OpenID4VP/.well-known/jar-issuer' not bound to any function"
```

**Causa:** Il backend OpenID4VP non ha un endpoint che espone i metadati JAR.

**Path richiesto:**
- `OpenID4VP/.well-known/jar-issuer`

**Source codice (pyeudiw):**
- `pyeudiw/trust/handler/direct_trust_jar.py:7` - DEFAULT: `/.well-known/jar-issuer`
- Test reference: `pyeudiw/tests/trust/handler/test_direct_trust_jar.py:82` - "openid4vp/.well-known/jar-issuer"

## Architettura Attuale

### Configurazione SATOSA (proxy_conf.yaml)

**Backend Modules Caricati:**
```yaml
BACKEND_MODULES:
  - conf/backends/saml2_backend.yaml
  - conf/backends/spidsaml2_backend.yaml
  - conf/backends/ciesaml2_backend.yaml
  - conf/backends/pyeudiw_backend.yaml          # OpenID4VP Backend ✓
  - conf/backends/cieoidc_backend.yaml
```

**Frontend Modules Caricati:**
```yaml
FRONTEND_MODULES:
  - conf/frontends/saml2_frontend.yaml
  - conf/frontends/oidcop_frontend.yaml         # SATOSA-oidcop ✓
  - conf/frontends/openid4vci_frontend.yaml     # OpenID4VCI Frontend ✓
```

**NOTA:** Il frontend OpenID4VP **non è caricato**.

### Backend OpenID4VP (pyeudiw_backend.yaml)

**Configurazione:**
- **Module:** `pyeudiw.satosa.backends.openid4vp.openid4vp.OpenID4VPBackend`
- **Name:** `OpenID4VP`
- **Endpoints Configurati:**
  - `/pre-request` - PreRequestHandler
  - `/response-uri` - ResponseHandler
  - `/request-uri` - RequestHandler
  - `/status` - StatusHandler
  - `/redirect-uri` - GetResponseHandler

**Trust Handlers Abilitati:**
- Federation Handler (configurato)
- X509Handler (configurato)
- DirectTrustSdJwtVc (commentato/disabled)
- DirectTrustJar (commentato/disabled)

### Frontend OpenID4VCI (openid4vci_frontend.yaml)

**Configurazione:**
- **Module:** `pyeudiw.satosa.frontends.openid4vci.openid4vci.OpenID4VCIFrontend`
- **Name:** `OpenID4VCI`
- **Endpoints Configurati:**
  - `/as/par` - ParHandler
  - `/credential` - CredentialHandler
  - `/authorize` - AuthorizationHandler
  - `/token` - TokenHandler
  - `/credential-qrcode` - CredentialOfferQrCodeHandler
  - `.well-known/openid-credential-issuer` - CredentialIssuerMetadataHandler ✓
  - `.well-known/oauth-authorization-server` - OauthAuthorizationServerMetadataHandler ✓
  - `/.well-known/openid-federation` - MetadataHandler ✓
  - `/status` - StatusListHandler

## Flussi di Comunicazione

### Flow 1: Emissione Credenziale (OpenID4VCI - Issuer ← Wallet)

```
Wallet (Holder)
    ↓
    ├─ GET /.well-known/openid-credential-issuer
    │  └─ [SATOSA Frontend OpenID4VCI]
    │     └─ CredentialIssuerMetadataHandler ✓
    │
    ├─ POST /as/par (PAR request)
    │  └─ [SATOSA Frontend OpenID4VCI]
    │     └─ ParHandler ✓
    │
    ├─ GET /authorize (authorization)
    │  └─ [SATOSA Frontend OpenID4VCI]
    │     └─ AuthorizationHandler ✓
    │
    ├─ POST /token (get token)
    │  └─ [SATOSA Frontend OpenID4VCI]
    │     └─ TokenHandler ✓
    │
    └─ POST /credential (get credential)
       └─ [SATOSA Frontend OpenID4VCI]
          └─ CredentialHandler ✓
```

### Flow 2: Presentazione Credenziale (OpenID4VP - Verifier ← Wallet)

```
Wallet (Holder)
    ↓
    ├─ GET OpenID4VP/.well-known/openid-configuration (trust discovery)
    │  ⚠️  Path: "OpenID4VP/.well-known/openid-configuration"
    │  └─ NOT CONFIGURED
    │
    ├─ GET OpenID4VP/.well-known/jar-issuer (trust discovery)
    │  ⚠️  Path: "OpenID4VP/.well-known/jar-issuer"
    │  └─ NOT CONFIGURED - 404 ERROR ❌
    │
    └─ Presentation flow (after trust check):
       ├─ GET OpenID4VP/request-uri?request_uri=...
       │  └─ [SATOSA Backend OpenID4VP]
       │     └─ RequestHandler ✓
       │
       └─ POST OpenID4VP/response-uri
          └─ [SATOSA Backend OpenID4VP]
             └─ ResponseHandler ✓
```

### Flow 3: Trust Chain Discovery - Direct Trust (SD-JWT VC)

```
Verifier (Backend OpenID4VP)
    ├─ Needs to verify issuer (credential issuer)
    ├─ Config: direct_trust_sd_jwt_vc (COMMENTED OUT)
    │
    └─ Fallback to Federation Handler
       └─ Requests issuer metadata from Trust Anchor
```

**Expected Endpoint:**
- `https://<issuer>/.well-known/jwt-vc-issuer/vct`

**Test Reference:**
- `pyeudiw/tests/trust/handler/test_direct_trust.py:42`
- Expected: `"https://credential-issuer.example/.well-known/jwt-vc-issuer/vct"`

## Tabella Endpoint Mancanti

| Path Richiesto | Component | Handler | Endpoint | Status |
|---|---|---|---|---|
| `/.well-known/jwt-vc-issuer/...` | Frontend OpenID4VCI | DirectTrustSdJwtVc | ❌ NON CONFIGURATO | Deve essere aggiunto |
| `OpenID4VP/.well-known/jar-issuer` | Backend OpenID4VP | DirectTrustJar | ❌ NON CONFIGURATO | Deve essere aggiunto |
| `OpenID4VP/.well-known/openid-configuration` | Backend OpenID4VP | Federation/OpenID Discovery | ❌ NON CONFIGURATO | Dovrebbe esistere |

## Chi Richiede Cosa

### Wallet (IT-Wallet Instance Demo)

Il wallet ricerca i metadati della fiducia prima di interagire con issuer/verifier:

1. **Durante Issuance:**
   - Wallet richiede: `GET /.well-known/openid-credential-issuer`
   - Via: Frontend OpenID4VCI
   - Per: Scoprire endpoint di issuance

2. **Durante Presentation:**
   - Wallet richiede: `GET OpenID4VP/.well-known/jar-issuer`
   - Via: Backend OpenID4VP (non configurato)
   - Per: Scoprire JWK per verificare i signed authorization requests

### Backend OpenID4VP (pyeudiw)

Quando riceve una richiesta di presentazione:

1. Verifica la fiducia nel wallet (holder)
2. Verifica la fiducia nelle credenziali presentate
   - Richiede: `GET issuer/.well-known/jwt-vc-issuer`
   - Per: Ottenere JWK pubbliche dell'emittente

### Frontend OpenID4VCI (pyeudiw)

Durante l'emissione, potrebbe aver bisogno di:

1. Verificare trust chain degli emittenti
2. Esporre i propri metadati di trust
   - Dovrebbe rispondere a: `GET /.well-known/jwt-vc-issuer`
   - Per: Permettere verificatori di validare credenziali emesse

## Causa Root Analysis

### Problema 1: Trust Handler Configuration

Nel file `pyeudiw_backend.yaml`, i trust handler per la verifica diretta sono commentati:

```yaml
# direct_trust_sd_jwt_vc:
#  module: pyeudiw.trust.handler.direct_trust_sd_jwt_vc
#  class: DirectTrustSdJwtVc
#  config:
#    cache_ttl: 0
#    httpc_params: *httpc_params
#    jwk_endpoint: /.well-known/jwt-vc-issuer

# direct_trust_jar:
#   module: pyeudiw.trust.handler.direct_trust_jar
#   class: DirectTrustJar
#   config:
#     cache_ttl: 0
#     httpc_params: *httpc_params
#     jwk_endpoint: /.well-known/jar-issuer
```

Quando disabilitati, il backend fa fallback a Federation Handler, che tenta di trovare le informazioni tramite il trust anchor.

### Problema 2: Missing Well-Known Endpoints

Nessuno dei seguenti endpoint è esposto:

1. **Backend OpenID4VP:**
   - `/.well-known/jar-issuer` (per JAR trust)
   - `/.well-known/openid-configuration` (OpenID Connect discovery)

2. **Frontend OpenID4VCI:**
   - `/.well-known/jwt-vc-issuer` (per SD-JWT VC trust)

Questi endpoint dovrebbero essere esposti da SATOSA in modo che external parties possano scoprire la metadata.

## Flusso Effettivo (Debugging Path)

### Passo 1: Wallet Presentation Request

```
Wallet → GET /OpenID4VP/.well-known/jar-issuer
         ↓ [SATOSA routes to Backend OpenID4VP]
         ? No endpoint configured
         ↓
         404 Error: "URL-path not bound to any endpoint function"
```

### Passo 2: Error Handling

```
SATOSA catches the 404
         ↓
         Logs: 'OpenID4VP/.well-known/jar-issuer' not bound to any function
         ↓
         Returns error to wallet
         ↓
Wallet cannot proceed with trust verification
```

## Soluzione Consigliata

### Option 1: Abilitare Trust Handler Diretti

Nel file `pyeudiw_backend.yaml`, decommentare e configurare:

```yaml
trust:
  direct_trust_jar:
    module: pyeudiw.trust.handler.direct_trust_jar
    class: DirectTrustJar
    config:
      cache_ttl: 0
      httpc_params: *httpc_params
      jwk_endpoint: /.well-known/jar-issuer
```

Questo permette al backend di presentare i propri JWK senza interrogare un trust anchor esterno.

### Option 2: Aggiungere Endpoint Well-Known

Aggiungere endpoints nel backend/frontend che espongono i metadati di trust:

```yaml
endpoints:
  jar_issuer_metadata:
    module: pyeudiw.satosa.backends.openid4vp.endpoints.jar_issuer_metadata_endpoint
    class: JarIssuerMetadataHandler
    path: /.well-known/jar-issuer
```

### Option 3: Configurare Frontend OpenID4VP

Aggiungere il frontend OpenID4VP nel proxy_conf.yaml:

```yaml
FRONTEND_MODULES:
  - conf/frontends/openid4vp_frontend.yaml  # Missing!
```

(Se esiste un file di configurazione per il frontend OpenID4VP)

## Tracciamento delle Richieste - Request Flow

```
┌─────────────────────────────────────────────────────────────┐
│ WALLET (IT-Wallet Instance Demo - Client)                   │
│ Richiede: GET /OpenID4VP/.well-known/jar-issuer             │
│ Client-ID: openid_federation:https://...                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ NGINX / REVERSE PROXY                                       │
│ Route: /OpenID4VP/ → iam-proxy-italia container             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ SATOSA (satosa.base.run)                                    │
│ Path: "/OpenID4VP/.well-known/jar-issuer"                   │
│ Method: GET                                                 │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ SATOSA Route Mapper                                         │
│ ├─ Estrae backend name: "OpenID4VP"                         │
│ ├─ Estrae path: "/.well-known/jar-issuer"                   │
│ ├─ Cerca in Backend OpenID4VP endpoints...                  │
│ └─ NOT FOUND ❌                                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ ERROR HANDLER (satosa.base.run:320)                         │
│ Eccezione: 'URL-path not bound to any endpoint function'    │
│ Error: "'OpenID4VP/.well-known/jar-issuer' not bound"       │
│ Status: 400 Bad Request                                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ WALLET (Client)                                             │
│ Riceve: Error Response (400)                                │
│ Azione: Cannot proceed with trust verification              │
└─────────────────────────────────────────────────────────────┘
```

## Key Files Involved

### SATOSA Configuration
- **Main Config:** `Docker-compose/iam-proxy-italia-project/proxy_conf.yaml`
  - Line 15-24: Backend modules
  - Line 26-31: Frontend modules (missing OpenID4VP frontend)

- **Backend OpenID4VP Config:** `Docker-compose/iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml`
  - Lines 1-2: Backend definition
  - Lines 11-35: Endpoints definition (no well-known endpoints)
  - Lines 230-285: Trust configuration (direct handlers commented out)

- **Frontend OpenID4VCI Config:** `Docker-compose/iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml`
  - Lines 1-2: Frontend definition
  - Lines 6-40: Endpoints definition
  - Lines 49-57: Well-known endpoints (configured ✓)

### PyEUDIW Source
- **Direct Trust JAR Handler:** `eudi-wallet-it-python/pyeudiw/trust/handler/direct_trust_jar.py`
  - Line 7: DEFAULT_JARISSUER_METADATA_ENDPOINT = "/.well-known/jar-issuer"

- **Direct Trust SD-JWT VC Handler:** `eudi-wallet-it-python/pyeudiw/trust/handler/direct_trust_sd_jwt_vc.py`
  - Line 9: DEFAULT_SDJWTVC_METADATA_ENDPOINT = "/.well-known/jwt-vc-issuer"

- **Test Cases:** `eudi-wallet-it-python/pyeudiw/tests/trust/handler/test_direct_trust_jar.py`
  - Lines 77-87: Expected paths for JAR issuer metadata

## Ipotesi sui Flussi di Richiesta

### Hypothesis 1: Wallet Discovery Phase

Durante il primo accesso, il wallet cerca i metadati di fiducia:

```
Wallet → GET /OpenID4VP/.well-known/jar-issuer
         └─ Looking for issuer JWK and metadata
         └─ For direct trust verification (bypassing trust anchor)
```

### Hypothesis 2: Issuer Verification Phase

Dopo aver ricevuto una credenziale, il wallet verifica l'emittente:

```
Wallet → GET /<issuer>/.well-known/jwt-vc-issuer/vct
         └─ Looking for VCT-specific JWK from issuer
         └─ For credential validation
```

### Hypothesis 3: Authorization Request Verification

Il verifier firma gli authorization request:

```
Verifier → Signs authorization request with /.well-known/jar-issuer key
Wallet → GET OpenID4VP/.well-known/jar-issuer
         └─ Retrieves issuer's public JWK
         └─ Verifies signature on authorization request
```

## Domande Aperte

1. **Chi richiede `.well-known/jwt-vc-issuer/OpenID4VCI`?**
   - È il wallet che cerca metadati del frontend OpenID4VCI?
   - O è un verifier esterno che cerca metadati dell'emittente?

2. **Dove viene generato l'authorization request con JAR?**
   - Backend OpenID4VP genera la richiesta di presentazione?
   - Dovrebbe firma essa stessa con le JWK da `/.well-known/jar-issuer`?

3. **Dovrebbe OpenID4VP esporre un frontend?**
   - Il backend OpenID4VP dovrebbe avere un frontend associato?
   - O è sempre un backend che interagisce con frontend OpenID4VCI?

## Prossimi Step per Debugging

1. **Abilitare logging dettagliato:**
   - Attivare DEBUG logging per SATOSA routing
   - Attivare DEBUG logging per pyeudiw trust handlers

2. **Tracciare client requests:**
   - Chi fa la richiesta a `.well-known/jwt-vc-issuer/OpenID4VCI`?
   - Da quale indirizzo IP?
   - Con quali header?

3. **Verificare configurazione trust:**
   - Quali trust handler dovrebbero essere abilitati?
   - Dovrebbero essere configurati come "direct" o "federation"?

4. **Test endpoint exposure:**
   - Fare richieste manuali ai well-known endpoints
   - Verificare che SATOSA le instrada correttamente

---

**Last Updated:** 2026-11-12 20:16 UTC+1
**Status:** Analysis Phase - Ready for Implementation
