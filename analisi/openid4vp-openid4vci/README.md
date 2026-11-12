# IAM Proxy Italia OpenID4VP/OpenID4VCI Investigation Documentation

## Investigation Summary

This investigation was conducted on **2026-11-12** to analyze and debug two critical errors in the IAM Proxy Italia system:

1. **Error 1:** `.well-known/jwt-vc-issuer/OpenID4VCI` endpoint not bound
2. **Error 2:** `OpenID4VP/.well-known/jar-issuer` endpoint not bound

These errors occur during OpenID4VCI (credential issuance) and OpenID4VP (credential presentation) flows and prevent proper trust discovery.

---

## Document Index

### 1. **INVESTIGATION_SUMMARY.md** ⭐ START HERE
   - **Purpose:** Executive summary of findings
   - **Content:**
     - Key findings (2 critical issues identified)
     - Root cause analysis
     - Component interaction flows
     - Impact assessment
     - Recommended solutions
   - **Audience:** Project leads, architects, decision makers
   - **Read Time:** 15-20 minutes

### 2. **openid4vp_openid4vci_debug_analysis.md**
   - **Purpose:** Detailed technical analysis
   - **Content:**
     - Error logs with full context
     - Architecture of current system
     - Backend and frontend configurations
     - Communication flows between components
     - Trust discovery processes
     - Configuration gaps enumerated
     - Status of each endpoint (✓ working vs ❌ missing)
   - **Audience:** System engineers, architects
   - **Read Time:** 30-45 minutes
   - **Keywords:** "Configuration", "Architecture", "Backend/Frontend", "Trust Handlers"

### 3. **request_tracing_guide.md**
   - **Purpose:** Per-request analysis and tracing
   - **Content:**
     - Detailed breakdown of each error request
     - Why each request fails
     - Path routing flow diagrams
     - Client behavior analysis
     - Expected vs actual behavior table
     - Common pattern identification
   - **Audience:** Debuggers, QA engineers, security analysts
   - **Read Time:** 20-30 minutes
   - **Keywords:** "Request 1", "Request 2", "Client", "Path Routing"

### 4. **flow_diagrams.txt**
   - **Purpose:** Visual representation of flows
   - **Content:**
     - Credential issuance flow diagram
     - Credential presentation flow diagram
     - SATOSA path routing logic
     - Component registration map
     - Trust discovery process flow
     - Error flow for Request 1 and Request 2
     - Component interaction map
     - Configuration state comparison
   - **Audience:** Visual learners, architects, trainers
   - **Read Time:** 15-25 minutes
   - **Best Used:** With a text editor that preserves formatting (VS Code, etc.)

### 5. **DEBUGGING_COMMANDS.md**
   - **Purpose:** Practical commands for testing and debugging
   - **Content:**
     - Quick endpoint testing commands
     - Log inspection commands
     - Configuration verification
     - Network tracing
     - SATOSA internal debugging
     - Wallet-side debugging
     - Database inspection (MongoDB)
     - Integration testing scripts
     - Performance monitoring
     - Automation scripts
   - **Audience:** Operators, support engineers, QA
   - **Read Time:** 10-15 minutes (reference document)
   - **Best Used:** Copy-paste ready commands with explanations

---

## Quick Navigation Guide

### "I need to..."

#### ...understand what's wrong
→ Start with: **INVESTIGATION_SUMMARY.md**
- Read sections: "Key Findings", "Root Cause Analysis"
- Time: 5 minutes

#### ...understand how it's supposed to work
→ Read: **openid4vp_openid4vci_debug_analysis.md**
- Read sections: "Architettura Attuale", "Flussi di Comunicazione"
- Time: 15 minutes

#### ...trace a specific request
→ Read: **request_tracing_guide.md**
- Read section: "Request 1 Path Flow" or "Request 2 Path Flow"
- Time: 10 minutes

#### ...visualize the system
→ Read: **flow_diagrams.txt**
- Look at: "Diagram 8: Component Interaction Map"
- Time: 10 minutes

#### ...test if something works
→ Use: **DEBUGGING_COMMANDS.md**
- Find the relevant "Test" section
- Time: 5 minutes (execution)

#### ...debug in production
→ Use: **DEBUGGING_COMMANDS.md**
- Find the relevant "Log Inspection" or "Network Tracing" section
- Time: 10 minutes (execution)

#### ...implement the fix
→ Read: **INVESTIGATION_SUMMARY.md** → "Recommended Solutions"
- Section: "Solution 1: Add Missing Well-Known Endpoints"
- Time: 10 minutes

---

## Key Findings Overview

### Issue 1: Missing `.well-known/jwt-vc-issuer` (OpenID4VCI Frontend)
- **Status:** ❌ MISSING
- **Severity:** HIGH
- **Who Requests:** External verifiers, wallets
- **Why Matters:** Cannot validate credentials issued by this system
- **Fix:** Add endpoint to OpenID4VCI frontend configuration

### Issue 2: Missing `.well-known/jar-issuer` (OpenID4VP Backend)
- **Status:** ❌ MISSING
- **Severity:** CRITICAL
- **Who Requests:** Wallet (IT-Wallet Instance Demo)
- **Why Matters:** Blocks entire credential presentation flow
- **Fix:** Add endpoint to OpenID4VP backend configuration

---

## Component Status Matrix

| Component | What Works | What's Missing | Priority |
|-----------|-----------|-----------------|----------|
| OpenID4VCI Frontend | ✓ Credential issuance | ❌ JWT-VC trust metadata | HIGH |
| OpenID4VP Backend | ✓ Presentation flow (partial) | ❌ JAR, OpenID config metadata | CRITICAL |
| Trust Handlers | ✓ Federation, X.509 | ⚠️ Direct handlers disabled | MEDIUM |
| Configuration | ✓ Mostly correct | ❌ Missing well-known endpoints | CRITICAL |

---

## Reading Recommendations by Role

### Project Manager
1. Read: INVESTIGATION_SUMMARY.md (full)
2. Focus: "Key Findings", "Impact Assessment", "Recommended Solutions"
3. Time: 15 minutes

### System Architect
1. Read: INVESTIGATION_SUMMARY.md (full)
2. Read: openid4vp_openid4vci_debug_analysis.md (Architecture sections)
3. Skim: flow_diagrams.txt (Diagram 8)
4. Time: 30 minutes

### Backend Developer (Implementation)
1. Read: INVESTIGATION_SUMMARY.md → "Recommended Solutions"
2. Read: request_tracing_guide.md → "Request Analysis"
3. Reference: DEBUGGING_COMMANDS.md (during implementation)
4. Time: 20 minutes

### DevOps / Operations
1. Skim: INVESTIGATION_SUMMARY.md → "Key Findings"
2. Use: DEBUGGING_COMMANDS.md (primary resource)
3. Reference: openid4vp_openid4vci_debug_analysis.md (when needed)
4. Time: 15 minutes

### QA / Tester
1. Read: openid4vp_openid4vci_debug_analysis.md → "Expected vs Actual Behavior"
2. Use: DEBUGGING_COMMANDS.md (test scripts)
3. Reference: flow_diagrams.txt (test scenarios)
4. Time: 25 minutes

### Security / Compliance
1. Read: INVESTIGATION_SUMMARY.md (full)
2. Read: request_tracing_guide.md → "Client Detection Methods"
3. Reference: flow_diagrams.txt (trust flow understanding)
4. Time: 20 minutes

---

## Implementation Checklist

If you're implementing the fix, use this checklist:

- [ ] Read INVESTIGATION_SUMMARY.md → "Recommended Solutions" → "Solution 1"
- [ ] Identify affected configuration files:
  - [ ] `Docker-compose/iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml`
  - [ ] `Docker-compose/iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml`
  - [ ] `iam-proxy-italia-project/conf/backends/pyeudiw_backend.yaml` (sync copy)
  - [ ] `iam-proxy-italia-project/conf/frontends/openid4vci_frontend.yaml` (sync copy)
- [ ] Add endpoints to configuration
- [ ] Verify YAML syntax is correct
- [ ] Rebuild Docker images (if needed)
- [ ] Restart containers
- [ ] Run health check: DEBUGGING_COMMANDS.md → "Health Check Script"
- [ ] Test full flows:
  - [ ] Credential issuance flow
  - [ ] Credential presentation flow
- [ ] Verify logs show no more ".well-known not bound" errors
- [ ] Deploy to production

---

## Cross-Reference: Error Messages to Documents

### Error Message Analysis

**Error 1:** `'.well-known/jwt-vc-issuer/OpenID4VCI' not bound to any function`
- → See: request_tracing_guide.md → "Request 1: jwt-vc-issuer/OpenID4VCI"
- → See: flow_diagrams.txt → "Diagram 6: Error Flow - Request 1"
- → See: DEBUGGING_COMMANDS.md → Test 2

**Error 2:** `'OpenID4VP/.well-known/jar-issuer' not bound to any function`
- → See: request_tracing_guide.md → "Request 2: OpenID4VP/.well-known/jar-issuer"
- → See: flow_diagrams.txt → "Diagram 7: Error Flow - Request 2"
- → See: DEBUGGING_COMMANDS.md → Test 2

---

## Key Concepts

### OpenID4VCI (OpenID for Credential Issuance)
- **Component:** Frontend in SATOSA
- **Role:** Issues credentials to holders
- **Main Endpoints:** `/authorize`, `/token`, `/credential`
- **Well-Known:** `/.well-known/openid-credential-issuer`
- **Missing:** `/.well-known/jwt-vc-issuer`
- **See:** flow_diagrams.txt → Diagram 1

### OpenID4VP (OpenID for Credential Presentation)
- **Component:** Backend in SATOSA
- **Role:** Verifies credentials from holders
- **Main Endpoints:** `/request-uri`, `/response-uri`, `/status`
- **Missing:** `/.well-known/jar-issuer`, `/.well-known/openid-configuration`
- **See:** flow_diagrams.txt → Diagram 2

### SATOSA (SATOSA Attribute Authority)
- **Role:** Acts as proxy/gateway between frontends and backends
- **Routing:** Maps paths to frontend/backend endpoints
- **Configuration:** `proxy_conf.yaml`
- **Problem:** Missing well-known endpoint registration
- **See:** flow_diagrams.txt → Diagram 3

### Trust Discovery
- **Purpose:** Wallets/verifiers discover trust metadata before interaction
- **Mechanism:** Standard `.well-known` endpoints
- **Used By:** Direct trust handlers, wallets, external verifiers
- **Problem:** Endpoints not exposed
- **See:** flow_diagrams.txt → Diagram 5

---

## File Locations in Repository

### Configuration Files Being Analyzed
```
/home/wert/DEV/IdentityPython/iam-proxy-italia/
├── Docker-compose/iam-proxy-italia-project/
│   ├── proxy_conf.yaml                          (Main SATOSA config)
│   └── conf/
│       ├── backends/pyeudiw_backend.yaml         (OpenID4VP config)
│       └── frontends/openid4vci_frontend.yaml    (OpenID4VCI config)
├── iam-proxy-italia-project/
│   ├── proxy_conf.yaml                          (Sync copy)
│   └── conf/
│       ├── backends/pyeudiw_backend.yaml         (Sync copy)
│       └── frontends/openid4vci_frontend.yaml    (Sync copy)
└── docs/
    └── OPENID4VP-SATOSA-BACKEND.md              (Reference documentation)
```

### Investigation Files (This Directory)
```
files/
├── README.md                                    (This file)
├── INVESTIGATION_SUMMARY.md                     (Executive summary)
├── openid4vp_openid4vci_debug_analysis.md       (Detailed analysis)
├── request_tracing_guide.md                     (Per-request analysis)
├── flow_diagrams.txt                            (Visual diagrams)
└── DEBUGGING_COMMANDS.md                        (Practical commands)
```

---

## Frequently Asked Questions (FAQ)

**Q1: Which request should I fix first?**
A: Fix Request 2 (jar-issuer) first - it blocks credential presentation entirely. Request 1 (jwt-vc-issuer) blocks external validation.

**Q2: Are these real bugs or configuration issues?**
A: Configuration issues. The code exists, it just isn't wired into SATOSA configuration.

**Q3: Can I work around this without fixing it?**
A: Partially - you can use federation trust as fallback, but direct trust discovery is more reliable and faster.

**Q4: Will this break anything if I implement the fix?**
A: No - you're only adding new endpoints, not modifying existing functionality.

**Q5: How do I test if my fix works?**
A: Use DEBUGGING_COMMANDS.md → "Health Check Script" - it tests both endpoints.

**Q6: Do I need to restart anything?**
A: Yes - SATOSA needs to reload configuration. Restart the iam-proxy-italia container.

**Q7: Is this a security issue?**
A: No - these are public metadata endpoints used for trust discovery.

**Q8: Which version of pyeudiw has this code?**
A: The code is in the pinned commit in pyproject.toml. Check with grep in eudi-wallet-it-python/pyeudiw/

---

## Additional References

### Official Specifications
- **OpenID4VCI:** https://www.ietf.org/archive/id/draft-ietf-oauth-openid4vci-06.html
- **OpenID4VP:** https://www.ietf.org/archive/id/draft-ietf-oauth-openid4vp-xx.html
- **JAR (RFC 9101):** https://www.ietf.org/rfc/rfc9101.html
- **SD-JWT VC:** https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-06.html

### Repository Documentation
- OPENID4VP-SATOSA-BACKEND.md (in docs/)
- OPENID4VCI.md (in docs/ of eudi-wallet-it-python)

### Related Issues
- See TODO.md for related issues in the main repo
- Error logs from production deployment

---

## Investigation Metadata

- **Investigation Date:** 2026-11-12
- **Duration:** Comprehensive analysis completed in single session
- **Scope:** Error tracing, root cause analysis, solution design
- **Status:** ✓ COMPLETE - Ready for implementation
- **Next Phase:** Implement missing endpoints (estimated 1-2 hours)
- **Testing Phase:** 1-2 hours (unit tests + integration tests)

---

## Document Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-11-12 | Initial investigation complete |

---

## Support & Questions

If you have questions about this investigation:

1. Check FAQ section above
2. Cross-reference using "Cross-Reference: Error Messages to Documents"
3. Look up your role in "Reading Recommendations by Role"
4. Consult DEBUGGING_COMMANDS.md for hands-on testing
5. Run health check script to verify your environment

---

**Investigation Lead:** AI Assistant using Copilot SDK
**Last Updated:** 2026-11-12 20:16 UTC+1
**Status:** Ready for Implementation
