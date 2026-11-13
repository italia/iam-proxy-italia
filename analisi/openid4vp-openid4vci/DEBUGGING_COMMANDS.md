# Practical Debugging Commands - OpenID4VP/OpenID4VCI

## Quick Endpoint Testing

### Test 1: Check if OpenID4VCI endpoints are responding

```bash
# Well-known credential issuer metadata
curl -v https://iam-proxy-italia.example.org/.well-known/openid-credential-issuer

# Expected Response (200 OK):
# {
#   "credential_issuer": "https://iam-proxy-italia.example.org/OpenID4VCI",
#   "credential_endpoint": "https://iam-proxy-italia.example.org/OpenID4VCI/credential",
#   "jwks": {...},
#   ...
# }

# Well-known OAuth authorization server metadata
curl -v https://iam-proxy-italia.example.org/.well-known/oauth-authorization-server

# Expected Response (200 OK): OAuth metadata with supported algorithms, endpoints, etc.

# Well-known openid-federation metadata
curl -v https://iam-proxy-italia.example.org/.well-known/openid-federation

# Expected Response (200 OK): Federation entity configuration
```

### Test 2: Check if OpenID4VP endpoints are responding

```bash
# Try to get verifier metadata (currently missing)
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Expected Response: 404 or 400 (currently broken)
# Should be (200 OK after fix):
# {
#   "jwks": [
#     {
#       "kty": "RSA",
#       "use": "sig",
#       "alg": "RS256",
#       "e": "AQAB",
#       "n": "...",
#       "kid": "..."
#     }
#   ]
# }

# Try openid-configuration
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/openid-configuration

# Expected Response: 404 or 400 (currently broken)
```

### Test 3: Check if missing endpoints are truly missing

```bash
# Test the first error path
curl -v https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer/OpenID4VCI

# Response: 400 Bad Request
# Error: 'URL-path is not bound to any endpoint function'

# Test the second error path
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Response: 400 Bad Request
# Error: 'URL-path is not bound to any endpoint function'
```

---

## Log Inspection Commands

### View recent SATOSA logs

```bash
# Follow logs in real-time (if running in Docker)
docker-compose logs -f iam-proxy-italia

# View last 100 lines of logs
docker-compose logs --tail=100 iam-proxy-italia

# View logs with timestamps and errors only
docker-compose logs iam-proxy-italia | grep -i error

# View specific error message
docker-compose logs iam-proxy-italia | grep "well-known/jar-issuer"

# View complete error context (10 lines before and after)
docker-compose logs iam-proxy-italia | grep -B10 -A10 "well-known/jar-issuer"
```

### Check local logs (if in Docker container)

```bash
# Inside container
tail -100 /home/iam-proxy-italia-project/logs/spid.log
tail -100 /home/iam-proxy-italia-project/logs/oidcop_debug.log
tail -100 /home/iam-proxy-italia-project/logs/saml2_debug.log

# Or via docker exec
docker exec iam-proxy-italia tail -100 /home/iam-proxy-italia-project/logs/spid.log
```

### Monitor SATOSA routing in real-time

```bash
# Set environment variable for debug logging
export SATOSA_LOG_LEVEL=DEBUG

# Run with debug output
docker-compose up iam-proxy-italia 2>&1 | tee satosa_debug.log

# Or modify proxy_conf.yaml logging level to DEBUG temporarily
```

---

## Configuration Inspection Commands

### Verify SATOSA is loading correct configuration

```bash
# Check which backends are loaded
docker exec iam-proxy-italia python -c "
import yaml
with open('proxy_conf.yaml') as f:
    config = yaml.safe_load(f)
    print('Backends:')
    for backend in config.get('BACKEND_MODULES', []):
        print(f'  - {backend}')
    print()
    print('Frontends:')
    for frontend in config.get('FRONTEND_MODULES', []):
        print(f'  - {frontend}')
"

# View raw configuration
docker exec iam-proxy-italia cat proxy_conf.yaml | head -50

# Check if pyeudiw_backend.yaml is valid YAML
docker exec iam-proxy-italia python -c "
import yaml
try:
    with open('conf/backends/pyeudiw_backend.yaml') as f:
        yaml.safe_load(f)
    print('✓ pyeudiw_backend.yaml is valid YAML')
except Exception as e:
    print(f'✗ Error: {e}')
"

# Check if openid4vci_frontend.yaml is valid YAML
docker exec iam-proxy-italia python -c "
import yaml
try:
    with open('conf/frontends/openid4vci_frontend.yaml') as f:
        yaml.safe_load(f)
    print('✓ openid4vci_frontend.yaml is valid YAML')
except Exception as e:
    print(f'✗ Error: {e}')
"
```

### Verify endpoints are registered

```bash
# Check what endpoints pyeudiw_backend registers
docker exec iam-proxy-italia python << 'EOF'
import yaml

with open('conf/backends/pyeudiw_backend.yaml') as f:
    config = yaml.safe_load(f)
    
print("OpenID4VP Backend Endpoints:")
for name, endpoint in config.get('config', {}).get('endpoints', {}).items():
    path = endpoint.get('path', 'NO PATH')
    print(f"  - {name}: {path}")

print("\nMissing endpoints:")
print("  - jar_issuer_metadata: /.well-known/jar-issuer")
print("  - openid_configuration: /.well-known/openid-configuration")
EOF

# Check what endpoints openid4vci_frontend registers
docker exec iam-proxy-italia python << 'EOF'
import yaml

with open('conf/frontends/openid4vci_frontend.yaml') as f:
    config = yaml.safe_load(f)
    
print("OpenID4VCI Frontend Endpoints:")
for name, endpoint in config.get('config', {}).get('endpoints', {}).items():
    path = endpoint.get('path', 'NO PATH')
    print(f"  - {name}: {path}")

print("\nMissing endpoints:")
print("  - jwt_vc_issuer_metadata: /.well-known/jwt-vc-issuer")
EOF
```

---

## Network Tracing Commands

### Capture HTTP requests to well-known endpoints

```bash
# Using tcpdump (requires root/sudo)
sudo tcpdump -i any -n host iam-proxy-italia.example.org -A | grep -B5 -A10 "well-known"

# Save to file for later analysis
sudo tcpdump -i any -n host iam-proxy-italia.example.org -w capture.pcap

# Convert to text
tcpdump -A -r capture.pcap | grep -B5 -A5 "well-known"

# Using tshark (part of Wireshark)
tshark -i any -f "host iam-proxy-italia.example.org" -Y "http" -T fields -e http.request.uri
```

### Check nginx access logs

```bash
# If nginx is in front (Docker)
docker-compose logs nginx | grep well-known

# If nginx is running locally
tail -f /var/log/nginx/access.log | grep well-known

# Search for specific paths
docker-compose logs nginx | grep "jar-issuer\|jwt-vc-issuer"

# Count occurrences
docker-compose logs nginx | grep -c "jar-issuer"
```

### Use curl with verbose output

```bash
# Show request and response headers
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Show only headers
curl -I https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Follow redirects and show verbose
curl -vL https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Save response to file
curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer > response.json 2> response_headers.txt

# Test with custom headers
curl -v \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer
```

---

## SATOSA Internal Debugging

### Enable detailed SATOSA logging

```bash
# Modify proxy_conf.yaml temporarily
docker exec iam-proxy-italia sed -i 's/level: INFO/level: DEBUG/g' proxy_conf.yaml

# Restart SATOSA
docker-compose restart iam-proxy-italia

# View debug logs
docker-compose logs -f iam-proxy-italia | grep -i "DEBUG\|endpoint\|route"
```

### Check SATOSA routing logic

```bash
# Create a test script to trace routing
docker exec iam-proxy-italia python << 'EOF'
# This would require importing SATOSA internals
# Would need to mock the request and check routing
import sys
sys.path.insert(0, '/home/iam-proxy-italia-project')

# Try to import and check loaded modules
try:
    from satosa.base import SASOManager
    # manager = SASOManager(config_path='proxy_conf.yaml')
    print("SATOSA modules loaded successfully")
except Exception as e:
    print(f"Error loading SATOSA: {e}")
EOF
```

---

## Wallet-Side Debugging

### Check IT-Wallet Instance Demo logs

```bash
# If wallet is running in Docker
docker-compose logs wallet-instance-demo | grep "well-known\|jar-issuer\|jwt-vc"

# Follow wallet logs in real-time
docker-compose logs -f wallet-instance-demo | grep -E "ERROR|trust|discovery"

# Check wallet configuration
docker exec wallet-instance-demo cat app/config/wallet_provider.yaml | grep -A10 "openid4vp\|openid4vci"
```

### Test wallet requests manually

```bash
# From wallet container
docker exec wallet-instance-demo curl -v https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# With wallet's session cookie (if applicable)
docker exec wallet-instance-demo curl -v \
  -H "Cookie: SESSION_ID=..." \
  https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer
```

---

## Database Inspection (MongoDB)

### Check MongoDB for session/trust data

```bash
# Connect to MongoDB
docker-compose exec mongo mongosh

# Inside mongo shell:

# List databases
show dbs

# Use pyeudiw database
use pyeudiw_openid4vp

# Check collections
show collections

# Look at sessions
db.sessions.find().limit(5).pretty()

# Look for trust-related data
db.trust_anchors.find().limit(5).pretty()
db.trust_sources.find().limit(5).pretty()

# Count documents
db.sessions.countDocuments()

# Find session by ID (from error logs)
db.sessions.findOne({session_id: "urn:uuid:44f67cf7-14c1-4f36-a1da-ea243dd36433"})
```

---

## Integration Testing Commands

### Complete flow test: Credential Issuance

```bash
#!/bin/bash

echo "=== Test 1: Credential Issuance Flow ==="
echo ""

echo "1. Get issuer metadata"
curl -s https://iam-proxy-italia.example.org/.well-known/openid-credential-issuer | jq '.credential_issuer'

echo ""
echo "2. Try to get JWT-VC issuer metadata (should fail)"
curl -s -w "\nStatus: %{http_code}\n" https://iam-proxy-italia.example.org/.well-known/jwt-vc-issuer | jq . || true

echo ""
echo "3. Get OAuth metadata"
curl -s https://iam-proxy-italia.example.org/.well-known/oauth-authorization-server | jq '.issuer'

echo ""
echo "=== Test 1: Credential Issuance - COMPLETE ==="
```

### Complete flow test: Credential Presentation

```bash
#!/bin/bash

echo "=== Test 2: Credential Presentation Flow ==="
echo ""

echo "1. Try to get verifier metadata (should fail)"
curl -s -w "\nStatus: %{http_code}\n" https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer | jq . || true

echo ""
echo "2. Try to get OpenID configuration (should fail)"
curl -s -w "\nStatus: %{http_code}\n" https://iam-proxy-italia.example.org/OpenID4VP/.well-known/openid-configuration | jq . || true

echo ""
echo "3. Try federation metadata"
curl -s -w "\nStatus: %{http_code}\n" https://iam-proxy-italia.example.org/OpenID4VP/.well-known/openid-federation | jq . || true

echo ""
echo "=== Test 2: Credential Presentation - COMPLETE ==="
```

---

## Performance Monitoring

### Check response times

```bash
# Measure response time to working endpoint
curl -o /dev/null -s -w "Time: %{time_total}s\nCode: %{http_code}\n" \
  https://iam-proxy-italia.example.org/.well-known/openid-credential-issuer

# Measure response time to broken endpoint
curl -o /dev/null -s -w "Time: %{time_total}s\nCode: %{http_code}\n" \
  https://iam-proxy-italia.example.org/OpenID4VP/.well-known/jar-issuer

# Compare multiple endpoints
for endpoint in \
  ".well-known/openid-credential-issuer" \
  ".well-known/oauth-authorization-server" \
  "OpenID4VP/.well-known/jar-issuer"
do
  echo "Testing $endpoint:"
  curl -o /dev/null -s -w "  Time: %{time_total}s, Code: %{http_code}\n" \
    https://iam-proxy-italia.example.org/$endpoint
done
```

---

## Automation: Quick Health Check

```bash
#!/bin/bash
# health_check.sh

echo "=== OpenID4VP/OpenID4VCI Health Check ==="
echo ""

# Test 1: OpenID4VCI Issuance Endpoints
echo "[1] OpenID4VCI Endpoints:"
for endpoint in \
  ".well-known/openid-credential-issuer" \
  ".well-known/oauth-authorization-server" \
  ".well-known/openid-federation" \
  ".well-known/jwt-vc-issuer"
do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://iam-proxy-italia.example.org/$endpoint)
  if [ "$status" = "200" ]; then
    echo "  ✓ $endpoint: $status"
  else
    echo "  ✗ $endpoint: $status"
  fi
done

echo ""

# Test 2: OpenID4VP Presentation Endpoints
echo "[2] OpenID4VP Endpoints:"
for endpoint in \
  "OpenID4VP/.well-known/jar-issuer" \
  "OpenID4VP/.well-known/openid-configuration" \
  "OpenID4VP/.well-known/openid-federation"
do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://iam-proxy-italia.example.org/$endpoint)
  if [ "$status" = "200" ]; then
    echo "  ✓ $endpoint: $status"
  else
    echo "  ✗ $endpoint: $status"
  fi
done

echo ""

# Test 3: Core Endpoints
echo "[3] Core Endpoints:"
for endpoint in \
  "OpenID4VCI/authorize" \
  "OpenID4VCI/token" \
  "OpenID4VCI/credential" \
  "OpenID4VP/request-uri" \
  "OpenID4VP/response-uri"
do
  status=$(curl -s -o /dev/null -w "%{http_code}" https://iam-proxy-italia.example.org/$endpoint)
  if [ "$status" = "400" ] || [ "$status" = "401" ] || [ "$status" = "405" ]; then
    echo "  ✓ $endpoint: $status (endpoint exists)"
  elif [ "$status" = "200" ]; then
    echo "  ✓ $endpoint: $status"
  else
    echo "  ✗ $endpoint: $status"
  fi
done

echo ""
echo "=== Health Check Complete ==="
```

---

## Troubleshooting Quick Reference

| Problem | Command | Expected Outcome |
|---------|---------|------------------|
| "jar-issuer not bound" error | `curl -v https://.../OpenID4VP/.well-known/jar-issuer` | 400 error (before fix), 200 OK (after fix) |
| "jwt-vc-issuer not bound" error | `curl -v https://.../​.well-known/jwt-vc-issuer` | 400 error (before fix), 200 OK (after fix) |
| SATOSA not routing correctly | `docker-compose logs iam-proxy-italia \| grep -i route` | DEBUG logs showing routing decisions |
| Configuration not loaded | `docker-compose logs iam-proxy-italia \| grep -i "loaded\|module"` | Confirmation that backend/frontend modules are loaded |
| Wallet cannot reach endpoint | `curl -v https://...` from wallet container | Shows network connectivity issues |
| Trust verification failing | `docker-compose logs \| grep -i "trust\|federation"` | Shows trust chain resolution errors |

---

**Last Updated:** 2026-11-12
**For:** IAM Proxy Italia OpenID4VP/OpenID4VCI Debugging
**Status:** Ready for Use
