# Investigation Summary: OpenID4VP/OpenID4VCI Backend/Frontend Flow Analysis

## Overview

This investigation analyzed two critical errors occurring in the IAM Proxy Italia system:
1. Missing `.well-known/jwt-vc-issuer` endpoint (OpenID4VCI Frontend)
2. Missing `.well-known/jar-issuer` endpoint (OpenID4VP Backend)

These errors prevent proper trust discovery in OpenID4VCI (credential issuance) and OpenID4VP (credential presentation) flows.

---

## Key Findings

### Finding 1: OpenID4VCI Frontend Is Partially Configured ✓ Mostly OK

**Status:** OpenID4VCI frontend exists and is registered in SATOSA.

**What Works:**
- ✓ Basic credential issuance endpoints exist
- ✓ Well-known/openid-credential-issuer (metadata discovery)
- ✓ Well-known/oauth-authorization-server (OAuth metadata)
- ✓ Well-known/openid-federation (federation metadata)
- ✓ Authorization endpoint (/authorize)
- ✓ Token endpoint (/token)
- ✓ Credential endpoint (/credential)

**What's Missing:**
- ❌ Well-known/jwt-vc-issuer (JWT-VC trust metadata)

**Impact:** External parties cannot verify credentials issued by this system because they cannot retrieve the issuer's public JWK.

**Error Log:**
```
[2026-11-12 16:01:40] [ERROR]: '.well-known/jwt-vc-issuer/OpenID4VCI' not bound to any function
```

---

### Finding 2: OpenID4VP Backend Lacks Well-Known Endpoints ❌ Critical

**Status:** OpenID4VP backend exists and is registered, but is missing critical metadata endpoints.

**What Works:**
- ✓ /pre-request (pre-authorization handling)
- ✓ /response-uri (credential presentation submission)
- ✓ /request-uri (authorization request retrieval)
- ✓ /status (presentation status check)
- ✓ /redirect-uri (post-presentation redirect)

**What's Missing:**
- ❌ /.well-known/jar-issuer (JAR signature verification metadata)
- ❌ /.well-known/openid-configuration (OpenID Connect discovery)
- ❌ /.well-known/openid-federation (federation discovery for verifier)

**Impact:** 
- Wallets cannot discover verifier capabilities
- Wallets cannot verify signed authorization requests
- Wallets cannot trust the verifier
- Complete presentation flow fails

**Error Log:**
```
[2026-11-12 20:11:11] [ERROR]: 'OpenID4VP/.well-known/jar-issuer' not bound to any function
```

---

## Root Cause Analysis

### Why These Endpoints Are Missing

**1. Trust Handler Configuration**

In `pyeudiw_backend.yaml`, the "Direct Trust" handlers are disabled:

```yaml
trust:
  # direct_trust_sd_jwt_vc: [COMMENTED OUT]
  # direct_trust_jar: [COMMENTED OUT]
  federation:  # Only federation is enabled
    module: pyeudiw.trust.handler.federation
    class: FederationHandler
```

**Problem:** Without direct trust handlers, the system doesn't expose the required `.well-known` endpoints.

**2. Missing SATOSA Endpoint Registrations**

Neither the backend nor frontend register the trust-related endpoints:

```yaml
# In pyeudiw_backend.yaml - endpoints section
# NO /.well-known/jar-issuer endpoint defined!

# In openid4vci_frontend.yaml - endpoints section
# NO /.well-known/jwt-vc-issuer endpoint defined!
```

**3. Architectural Decision**

- OpenID4VP is configured as **backend-only** (no frontend)
- OpenID4VCI is configured as **frontend-only** (no backend)
- This split means:
  - Wallet (client) talks to OpenID4VCI frontend for credential issuance
  - Wallet talks to OpenID4VP backend for credential presentation
  - But OpenID4VP backend doesn't expose its metadata like a frontend would

---

## Component Interaction Flow

### Current Architecture

```
WALLET (Client)
    │
    ├─ Issuance Flow
    │  └─ Talks to: SATOSA Frontend:OpenID4VCI (mostly works)
    │     └─ Finds metadata: /.well-known/openid-credential-issuer ✓
    │     └─ Cannot find: /.well-known/jwt-vc-issuer ❌
    │
    └─ Presentation Flow
       └─ Talks to: SATOSA Backend:OpenID4VP (partially works)
          ├─ Can execute presentation: /request-uri, /response-uri ✓
          └─ Cannot find metadata: /.well-known/jar-issuer ❌
                                   /.well-known/openid-configuration ❌
```

### Trust Discovery Problem

**OpenID4VCI (Issuer) Trust Flow:**
```
External Verifier → GET /.well-known/jwt-vc-issuer
                    └─ Expected: JSON with issuer JWK
                    └─ Actual: 404 Error
```

**OpenID4VP (Verifier) Trust Flow:**
```
Wallet → GET /OpenID4VP/.well-known/jar-issuer
         └─ Expected: JSON with verifier JWK
         └─ Actual: 404 Error
```

---

## Who Requests These Endpoints?

### Request 1: `.well-known/jwt-vc-issuer/OpenID4VCI`

**Requester:** 
- Likely an external verifier/relying party
- Or wallet during issuance flow

**When:**
- After receiving a credential from OpenID4VCI
- Before validating the credential signature

**Why:**
- Needs issuer's public key (JWK) to verify credential signature
- RFC Standard: Well-known endpoint for JWT-VC issuers

**Expected Response:**
```json
{
  "jwks": [
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "..."
    }
  ]
}
```

### Request 2: `OpenID4VP/.well-known/jar-issuer`

**Requester:** 
- Definitely the wallet (IT-Wallet Instance Demo)
- During credential presentation initiation

**When:**
- Before accepting authorization request from verifier
- During trust discovery phase

**Why:**
- Verifier signs authorization requests using JAR (RFC 9101)
- Wallet needs to verify these signatures
- JAR requires verifier's public key (JWK)

**Expected Response:**
```json
{
  "jwks": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "e": "AQAB",
      "n": "...",
      "kid": "..."
    }
  ]
}
```

---

## Configuration Gaps

### Gap 1: SATOSA Routing Configuration

**File:** `proxy_conf.yaml`

**Current State:**
```yaml
BACKEND_MODULES:
  - conf/backends/pyeudiw_backend.yaml     # ✓ Present

FRONTEND_MODULES:
  - conf/frontends/openid4vci_frontend.yaml # ✓ Present
  # ❌ MISSING: conf/frontends/openid4vp_frontend.yaml
```

**Issue:** 
- OpenID4VP only configured as backend
- No corresponding frontend to serve metadata

**Note:** This might be intentional - OpenID4VP as "verifier" may not need frontend behavior.

### Gap 2: Backend Endpoint Definitions

**File:** `pyeudiw_backend.yaml`

**Current Endpoints:**
```yaml
endpoints:
  pre_request:
    path: /pre-request
  response:
    path: /response-uri
  request:
    path: /request-uri
  status:
    path: /status
  get_response:
    path: /redirect-uri
```

**Missing Endpoints:**
```yaml
# These should be added:
jar_issuer_metadata:
  path: /.well-known/jar-issuer
openid_configuration:
  path: /.well-known/openid-configuration
federation_metadata:
  path: /.well-known/openid-federation
```

### Gap 3: Frontend Endpoint Definitions

**File:** `openid4vci_frontend.yaml`

**Current Well-Known Endpoints:**
```yaml
credential_issuer_metadata:
  path: '.well-known/openid-credential-issuer'
oauth_authorization_server_metadata:
  path: '.well-known/oauth-authorization-server'
metadata:
  path: '/.well-known/openid-federation'
```

**Missing Endpoints:**
```yaml
# This should be added:
jwt_vc_issuer_metadata:
  path: '/.well-known/jwt-vc-issuer'
```

### Gap 4: Trust Handler Configuration

**File:** `pyeudiw_backend.yaml`

**Current Trust Handlers:**
```yaml
trust:
  federation:
    # ✓ Federation trust enabled
  x509:
    # ✓ X.509 trust enabled
  # ❌ direct_trust_jar: COMMENTED OUT
  # ❌ direct_trust_sd_jwt_vc: COMMENTED OUT
```

**Why This Matters:**
- When direct trust handlers are disabled, the system only uses federation trust
- Federation requires a working trust anchor
- If trust anchor is unavailable or slow, operations fail

---

## Impact Assessment

### High Priority Issues

| Issue | Impact | Severity |
|-------|--------|----------|
| OpenID4VP `.well-known/jar-issuer` missing | Wallet cannot verify verifier's signatures | **CRITICAL** |
| OpenID4VP `.well-known/openid-configuration` missing | Wallet cannot discover verifier capabilities | **HIGH** |
| OpenID4VCI `.well-known/jwt-vc-issuer` missing | External parties cannot verify credentials | **HIGH** |

### Affected Flows

| Flow | Impact |
|------|--------|
| Credential Issuance | Wallet can issue credentials but cannot validate them later |
| Credential Presentation | Wallet cannot initiate presentation (blocks at trust discovery) |
| Cross-Entity Verification | External verifiers cannot validate issued credentials |

---

## Recommended Solutions

### Solution 1: Add Missing Well-Known Endpoints (Recommended)

**Priority:** CRITICAL

**Implementation:**
1. Add `jar_issuer_metadata` endpoint to OpenID4VP backend
2. Add `jwt_vc_issuer_metadata` endpoint to OpenID4VCI frontend
3. Add `openid_configuration` endpoint to OpenID4VP backend

**Benefits:**
- Enables direct trust discovery
- Reduces dependency on federation/trust anchor
- Faster trust verification
- Works even when trust anchor is unavailable

**Files to Modify:**
- `Docker-compose/iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml`
- `Docker-compose/iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml`
- `iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml`
- `iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml`

### Solution 2: Enable Direct Trust Handlers

**Priority:** MEDIUM (If Solution 1 is implemented, this becomes optional)

**Implementation:**
1. Uncomment `direct_trust_jar` handler in OpenID4VP backend
2. Uncomment `direct_trust_sd_jwt_vc` handler in backend/frontend as needed

**Benefits:**
- Signals to clients that direct trust is supported
- May be required by some standards

### Solution 3: Configure Federation Trust Fallback

**Priority:** MEDIUM (For resilience)

**Implementation:**
1. Ensure trust anchor is reliably accessible
2. Configure proper timeouts and retries
3. Add proper error handling

---

## Testing Recommendations

### Test 1: Direct Trust Discovery

```bash
# Test OpenID4VP metadata discovery
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Expected: 200 OK with JWK
# Currently: 400 Bad Request
```

### Test 2: Credential Issuance

```bash
# Complete credential issuance flow
# 1. Start issuance
# 2. Authorize
# 3. Receive credential
# 4. Verify credential (external verifier)
#    → Should succeed after Solution 1 is implemented
```

### Test 3: Credential Presentation

```bash
# Complete credential presentation flow
# 1. Initiate presentation
# 2. Discover verifier metadata (uses jar-issuer endpoint)
# 3. Verify authorization request signature
# 4. Submit presentation
# 5. Receive response
#    → Should succeed after Solution 1 is implemented
```

---

## Documentation References

### OpenID4VCI Specification
- Well-known endpoint: `/.well-known/openid-credential-issuer`
- JWT-VC issuer endpoint: `/.well-known/jwt-vc-issuer`
- Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-openid4vci-06.html

### OpenID4VP Specification
- Well-known discovery: `/.well-known/openid-configuration`
- JAR issuer metadata: `/.well-known/jar-issuer`
- Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-openid4vp-xx.html

### JAR (JWT Authorization Request) Specification
- RFC 9101: JSON Web Token (JWT) Secured Authorization Request (JAR)

### PyEUDIW Implementation
- Direct Trust SD-JWT VC: `pyeudiw/trust/handler/direct_trust_sd_jwt_vc.py`
- Direct Trust JAR: `pyeudiw/trust/handler/direct_trust_jar.py`
- Default endpoints defined in these files

---

## Key Questions Answered

**Q1: Where do these requests come from?**
- Request 1: External verifier or wallet (during credential validation)
- Request 2: Wallet (IT-Wallet Instance Demo) during presentation initiation

**Q2: Why are these endpoints missing?**
- Direct trust handlers are disabled (commented out)
- Well-known endpoints are not registered in SATOSA configuration

**Q3: What's the impact?**
- Wallet cannot verify verifier's authorization requests
- External parties cannot validate issued credentials
- Trust discovery fails, blocking credential flows

**Q4: How to fix?**
- Register well-known endpoints in backend/frontend configuration
- Optionally enable direct trust handlers
- Ensure federation trust fallback is configured

---

## Files Analyzed

### Configuration Files
- [proxy_conf.yaml](/home/wert/DEV/IdentityPython/iam-proxy-italia/Docker-compose/iam-proxy-italia-project/proxy_conf.yaml) - SATOSA main configuration
- [pyeudiw_backend.yaml](/home/wert/DEV/IdentityPython/iam-proxy-italia/Docker-compose/iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml) - OpenID4VP backend configuration
- [openid4vci_frontend.yaml](/home/wert/DEV/IdentityPython/iam-proxy-italia/Docker-compose/iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml) - OpenID4VCI frontend configuration

### Source Code Files
- `eudi-wallet-it-python/pyeudiw/trust/handler/direct_trust_jar.py` - JAR trust implementation
- `eudi-wallet-it-python/pyeudiw/trust/handler/direct_trust_sd_jwt_vc.py` - JWT-VC trust implementation
- `eudi-wallet-it-python/pyeudiw/tests/trust/handler/test_direct_trust_jar.py` - Test cases showing expected paths

### Related Files in Session
- [openid4vp_openid4vci_debug_analysis.md](./openid4vp_openid4vci_debug_analysis.md) - Detailed analysis
- [request_tracing_guide.md](./request_tracing_guide.md) - Request-by-request breakdown
- [flow_diagrams.txt](./flow_diagrams.txt) - Visual flow diagrams

---

## Conclusion

The IAM Proxy Italia system has a well-structured OpenID4VCI/OpenID4VP implementation but is missing critical trust discovery endpoints. The errors encountered are due to:

1. **Incomplete Endpoint Registration** in SATOSA configuration
2. **Disabled Direct Trust Handlers** that would expose these endpoints
3. **Federation-Only Trust Configuration** that requires external trust anchor

The solution involves adding well-known metadata endpoints to enable direct trust discovery. This is a configuration issue, not a code issue, and can be resolved by modifying the YAML configuration files.

**Recommended Action:** Implement Solution 1 (Add Missing Well-Known Endpoints) to enable proper trust discovery and unblock both credential issuance and presentation flows.

---

**Investigation Date:** 2026-11-12
**Status:** Complete - Ready for Implementation
**Next Phase:** Implement endpoints in configuration files
