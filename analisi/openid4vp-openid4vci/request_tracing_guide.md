# Request Tracing Guide - OpenID4VP/OpenID4VCI

## Request 1: jwt-vc-issuer/OpenID4VCI

### Error Log
```
[2026-11-12 16:01:40] [ERROR]: [urn:uuid:8e9cd267-4a87-4407-9e1b-942390ee2bc3]
'message': 'URL-path is not bound to any endpoint function'
'error': "'.well-known/jwt-vc-issuer/OpenID4VCI' not bound to any function"
'error_id': 'urn:uuid:8ba07fa4-3c53-42f0-b5ad-a1f8669bedfd'
```

### Request Breakdown
- **Path:** `.well-known/jwt-vc-issuer/OpenID4VCI`
- **Full URL (likely):** `https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer/OpenID4VCI`
- **Method:** `GET` (implied, used for metadata discovery)
- **Client ID:** Unknown (likely IT-Wallet demo or external verifier)
- **Purpose:** Discover JWT-VC issuer metadata for credential validation

### What's Happening

1. **Client makes request**
   ```
   GET /.well-known/jwt-vc-issuer/OpenID4VCI HTTP/1.1
   Host: iam-proxy-italia.example.org
   ```

2. **SATOSA path parsing**
   - SATOSA tries to parse the path
   - Looks for a route handler
   - Path format: `/.well-known/jwt-vc-issuer/OpenID4VCI`

3. **No matching endpoint**
   - Frontend OpenID4VCI has:
     - `.well-known/openid-credential-issuer` ✓
     - `.well-known/oauth-authorization-server` ✓
     - `/.well-known/openid-federation` ✓
   - But NOT `/.well-known/jwt-vc-issuer` ❌

4. **Error response**
   ```
   HTTP 400 Bad Request
   Content-Type: application/json
   
   {
     "message": "URL-path is not bound to any endpoint function",
     "error": "'.well-known/jwt-vc-issuer/OpenID4VCI' not bound to any function",
     "error_id": "urn:uuid:8ba07fa4-3c53-42f0-b5ad-a1f8669bedfd"
   }
   ```

### Possible Client Behaviors

#### Scenario A: External Verifier
- External verifier tries to validate a credential issued by this proxy
- Requests issuer's JWT-VC metadata to get public JWK
- Expected: `GET https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer`
- Actual: `GET https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer/OpenID4VCI`
- Issue: Path includes component name (OpenID4VCI) - likely dynamic path construction

#### Scenario B: Wallet Discovery
- Wallet discovers issuer capabilities
- Tries to learn what credential formats are supported
- Includes format type in path: `/OpenID4VCI` = OpenID4VCI format

### Key Question
**Is the path constructed by the client or by SATOSA?**

- If client-side: Wallet/verifier is adding the component name
- If SATOSA-side: SATOSA is routing and adding the frontend name to the path

### Evidence Collection

To determine the source:
1. Enable HTTP request logging at nginx/reverse proxy
2. Check if requests come with or without `/OpenID4VCI` suffix
3. Check pyeudiw wallet code for path construction
4. Check if external clients use the path

---

## Request 2: OpenID4VP/.well-known/jar-issuer

### Error Log
```
[2026-11-12 20:11:11] [ERROR]: [urn:uuid:44f67cf7-14c1-4f36-a1da-ea243dd36433]
'message': 'URL-path is not bound to any endpoint function'
'error': "'OpenID4VP/.well-known/jar-issuer' not bound to any function"
'error_id': 'urn:uuid:0e65ff9e-6902-4727-ac64-3adc68de8db8'
```

### Request Breakdown
- **Path:** `OpenID4VP/.well-known/jar-issuer`
- **Full URL (likely):** `https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer`
- **Method:** `GET` (implied, used for metadata discovery)
- **Client ID:** Unknown (likely IT-Wallet demo wallet)
- **Purpose:** Discover JAR (Signed Authorization Request) issuer metadata

### What's Happening

1. **Client makes request**
   ```
   GET /OpenID4VP/.well-known/jar-issuer HTTP/1.1
   Host: iam-proxy-italia.example.org
   ```

2. **SATOSA backend routing**
   - SATOSA identifies `OpenID4VP` as backend name
   - Tries to find endpoint `/.well-known/jar-issuer` in that backend
   - Backend endpoints configured:
     - `/pre-request` ✓
     - `/response-uri` ✓
     - `/request-uri` ✓
     - `/status` ✓
     - `/redirect-uri` ✓
   - But NOT `/.well-known/jar-issuer` ❌

3. **No matching endpoint**
   - The path `/.well-known/jar-issuer` is not registered as an endpoint
   - SATOSA returns 400 error

4. **Error response**
   ```
   HTTP 400 Bad Request
   Content-Type: application/json
   
   {
     "message": "URL-path is not bound to any endpoint function",
     "error": "'OpenID4VP/.well-known/jar-issuer' not bound to any function",
     "error_id": "urn:uuid:0e65ff9e-6902-4727-ac64-3adc68de8db8"
   }
   ```

### Client Behavior Analysis

#### Most Likely: Wallet Trust Discovery

```
IT-Wallet Instance Demo (Holder/Wallet)
    ↓
    Initiating presentation flow to Verifier (Backend OpenID4VP)
    ↓
    Steps:
    1. Learn about verifier's capabilities
    2. GET /OpenID4VP/.well-known/openid-configuration (discovery)
    3. GET /OpenID4VP/.well-known/jar-issuer (trust metadata)
    4. Verify that verifier's signed authorization requests are authentic
    ↓
    Response: 400 Error - Cannot verify verifier's signatures
    ↓
    Wallet: Cannot safely proceed with presentation
```

#### Why This Matters

The wallet NEEDS this endpoint because:
- Verifier sends signed authorization requests using JAR (RFC 9101)
- Wallet must verify the JWK used to sign these requests
- Wallet learns public JWK from `/.well-known/jar-issuer`
- Without this, wallet cannot validate authorization request signatures

### The OpenID4VP Backend Endpoints

Current configuration has:

```yaml
endpoints:
  pre_request:
    path: /pre-request              # Pre-request authorization
  response:
    path: /response-uri              # User sends VP here
  request:
    path: /request-uri               # Get authorization request
  status:
    path: /status                    # Check status
  get_response:
    path: /redirect-uri              # Redirect after presentation
```

**Missing:**
- `/.well-known/jar-issuer` - Expose verifier's JWK for JAR verification
- `/.well-known/openid-configuration` - OpenID Connect metadata
- `/.well-known/openid-federation` - Federation metadata (different from issuer)

### Solution Path

**Option 1: Add JAR Issuer Endpoint**

Add to `pyeudiw_backend.yaml` under `endpoints`:

```yaml
jar_issuer_metadata:
  module: pyeudiw.satosa.backends.openid4vp.endpoints.jar_issuer_metadata_endpoint
  class: JarIssuerMetadataHandler
  path: /.well-known/jar-issuer
```

This endpoint should:
- Export public JWK from `metadata_jwks[0]` or `metadata_jwks[3]` (the RS256 key for signing)
- Return JSON with `jwks` array
- Allow wallet to verify JAR signatures

**Option 2: Use Federation Discovery**

If Federation Trust is enabled:
- Wallet queries trust anchor instead of backend directly
- Trust anchor provides verifier metadata including JWK
- Requires working federation handler

**Option 3: Use Direct Trust JAR**

Enable the commented-out `direct_trust_jar` handler:

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

This tells the system:
- "I support direct JAR trust verification"
- "My JWK are available at /.well-known/jar-issuer"
- Wallet can then call that endpoint

---

## Request Path Analysis

### Request 1 Path Flow

```
CLIENT REQUEST
  URL: https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer/OpenID4VCI
  
NGINX REVERSE PROXY
  Route: /.well-known/jwt-vc-issuer/OpenID4VCI → iam-proxy-italia container:8000
  
SATOSA
  Path: /.well-known/jwt-vc-issuer/OpenID4VCI
  
SATOSA ROUTER
  ├─ Check if path starts with /<frontend_name>/
  │  └─ Does NOT start with /OpenID4VCI/ or /OpenID4VCP/ or /Saml2/ 
  │     (it's /.well-known/...)
  │
  ├─ Check if path starts with /<backend_name>/
  │  └─ Does NOT match any backend
  │
  └─ Route as root-level endpoint?
     └─ Check registered global endpoints
     └─ SATOSA frontends register:
        - FRONTEND:OpenID4VCI:/.well-known/openid-credential-issuer ✓
        - FRONTEND:OpenID4VCI:/.well-known/oauth-authorization-server ✓
        - FRONTEND:OpenID4VCI:/.well-known/openid-federation ✓
        - (No match for /.well-known/jwt-vc-issuer) ❌

ERROR: Path not bound to any endpoint function
```

### Request 2 Path Flow

```
CLIENT REQUEST
  URL: https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer
  
NGINX REVERSE PROXY
  Route: /OpenID4VP/.well-known/jar-issuer → iam-proxy-italia container:8000
  
SATOSA
  Path: /OpenID4VP/.well-known/jar-issuer
  
SATOSA ROUTER
  ├─ Check if path starts with /<backend_name>/
  │  └─ YES! Starts with /OpenID4VP/
  │  └─ Backend name: OpenID4VP
  │  └─ Remaining path: /.well-known/jar-issuer
  │
  └─ Get Backend OpenID4VP registered endpoints
     ├─ /pre-request
     ├─ /response-uri
     ├─ /request-uri
     ├─ /status
     ├─ /redirect-uri
     └─ (No match for /.well-known/jar-issuer) ❌

ERROR: Path 'OpenID4VP/.well-known/jar-issuer' not bound to any endpoint function
```

---

## Client Detection Methods

### Method 1: Log Analysis

Check SATOSA logs for:
```
- Request headers (User-Agent, Accept, etc.)
- Client IP address
- HTTP method
- Full URL path
- Request body (if POST)
```

### Method 2: Network Tracing

```bash
tcpdump -i any -n host iam-proxy-italia.example.org -w capture.pcap
tcpdump -A -r capture.pcap | grep -A5 -B5 "well-known/jwt-vc-issuer"
```

### Method 3: Reverse Proxy Logging

If using nginx, check:
```
/var/log/nginx/access.log
/var/log/nginx/error.log
```

Look for requests to `.well-known` paths.

### Method 4: Application-Level Tracing

Enable DEBUG logging in pyeudiw:

```python
# In pyeudiw/satosa/backends/openid4vp/openid4vp.py
# In pyeudiw/satosa/frontends/openid4vci/openid4vci.py

import logging
logger = logging.getLogger(__name__)
logger.debug(f"Incoming request: {self.request}")
logger.debug(f"Headers: {dict(self.request.headers)}")
logger.debug(f"Client IP: {self.request.remote_addr}")
```

---

## Expected vs Actual Behavior

### OpenID4VCI (Issuer)

| Aspect | Expected | Actual | Status |
|--------|----------|--------|--------|
| Frontend registered in SATOSA | ✓ | ✓ | ✓ OK |
| Credential offer endpoint | ✓ | ✓ | ✓ OK |
| Authorization endpoint | ✓ | ✓ | ✓ OK |
| Token endpoint | ✓ | ✓ | ✓ OK |
| Credential endpoint | ✓ | ✓ | ✓ OK |
| Well-known/credential-issuer | ✓ | ✓ | ✓ OK |
| Well-known/oauth-auth-server | ✓ | ✓ | ✓ OK |
| Well-known/jwt-vc-issuer | ✓ | ✗ | ❌ MISSING |
| Trust handler enabled | ✓ | Partial | ⚠️ Check |

### OpenID4VP (Verifier)

| Aspect | Expected | Actual | Status |
|--------|----------|--------|--------|
| Backend registered in SATOSA | ✓ | ✓ | ✓ OK |
| Pre-request endpoint | ✓ | ✓ | ✓ OK |
| Request-uri endpoint | ✓ | ✓ | ✓ OK |
| Response-uri endpoint | ✓ | ✓ | ✓ OK |
| Status endpoint | ✓ | ✓ | ✓ OK |
| Redirect-uri endpoint | ✓ | ✓ | ✓ OK |
| Well-known/openid-configuration | ✓ | ✗ | ❌ MISSING |
| Well-known/openid-federation | ✓ | ✗ | ❌ MISSING |
| Well-known/jar-issuer | ✓ | ✗ | ❌ MISSING |
| Trust handler enabled | ✓ | Partial | ⚠️ Check |

---

## Summary

### Request 1: `.well-known/jwt-vc-issuer/OpenID4VCI`

- **Source:** Unknown external party or wallet
- **Target:** OpenID4VCI Frontend (Issuer)
- **Purpose:** Get issuer's JWT-VC metadata and JWK
- **Why fails:** Endpoint not exposed in SATOSA configuration
- **Fix:** Add JAR issuer metadata endpoint to OpenID4VCI frontend

### Request 2: `OpenID4VP/.well-known/jar-issuer`

- **Source:** IT-Wallet Instance Demo (wallet)
- **Target:** OpenID4VP Backend (Verifier)
- **Purpose:** Get verifier's JWK to verify signed authorization requests
- **Why fails:** Endpoint not configured in backend
- **Fix:** Add JAR issuer metadata endpoint to OpenID4VP backend

### Common Pattern

Both are **trust discovery requests** trying to fetch public key material (JWK) via well-known endpoints. This is fundamental to both OpenID4VCI and OpenID4VP protocols.

---

**Document Version:** 1.0
**Last Updated:** 2026-11-12
