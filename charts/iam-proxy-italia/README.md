# IAM Proxy Italia Helm Chart

Helm chart for deploying IAM Proxy Italia (SATOSA SAML2/SPID proxy) on Kubernetes.

## Installation

### Basic Installation

```bash
helm install myrelease ./charts/iam-proxy-italia
```

### Installation with Custom Values

```bash
helm install myrelease ./charts/iam-proxy-italia -f custom-values.yaml
```

### Installation with CLI Overrides

```bash
helm install myrelease ./charts/iam-proxy-italia \
  --set satosa.hostname=iam.example.com \
  --set mongodb.host=mongodb.default.svc.cluster.local
```

## Secret Management

This chart manages sensitive data (passwords, encryption keys) using Kubernetes Secrets. You have two options:

### Option 1: Auto-Generated Secret (Default)

The chart will automatically create a Secret from values in `values.yaml`:

```yaml
secret:
  create: true

satosa:
  encryption:
    key: "your-secure-encryption-key"
    salt: "your-secure-salt"
    stateKey: "your-secure-state-key"
    userIdHashSalt: "your-secure-hash-salt"

mongodb:
  password: "your-mongodb-password"

mongodbBackend:
  password: "your-backend-password"

mongodbFrontend:
  password: "your-frontend-password"
```

The secret will be named using the release fullname (e.g., `myrelease-iam-proxy-italia`).

See `examples/auto-generated-secret.yaml` for a complete example.

### Option 2: Use Existing Secret

Create a secret manually and reference it in your values:

```bash
kubectl create secret generic my-satosa-secret \
  --from-literal=satosa-encryption-key='my-key' \
  --from-literal=satosa-salt='my-salt' \
  --from-literal=satosa-state-encryption-key='my-state-key' \
  --from-literal=satosa-user-id-hash-salt='my-hash-salt' \
  --from-literal=mongodb-password='my-db-password' \
  --from-literal=mongodb-backend-password='my-backend-password' \
  --from-literal=mongodb-frontend-password='my-frontend-password'
```

Then reference it:

```yaml
secret:
  create: false
  existingSecret: "my-satosa-secret"
```

See `examples/existing-secret.yaml` for a complete example.

### Required Secret Keys

When using an existing secret, it **must** contain these keys:

- `satosa-encryption-key` - Main encryption key for SATOSA
- `satosa-salt` - Salt for encryption
- `satosa-state-encryption-key` - State encryption key
- `satosa-user-id-hash-salt` - Salt for user ID hashing
- `mongodb-password` - MongoDB password
- `mongodb-backend-password` - MongoDB backend password
- `mongodb-frontend-password` - MongoDB frontend password

## Configuration

### Key Configuration Sections

#### SATOSA Configuration

```yaml
satosa:
  hostname: "localhost"
  debug: false                    # Boolean
  byDocker: true                  # Boolean
  baseDir: "/satosa_proxy"

  # Metadata fetching flags
  getIdemMdqKey: true             # Boolean
  getSpidIdpMetadata: true        # Boolean
  getFicepIdpMetadata: true       # Boolean
  getCieIdpMetadata: true         # Boolean

  # Keys configuration
  keys:
    mountPath: "/app/pki"
    privateKeyFilename: "privkey.pem"
    publicKeyFilename: "cert.pem"
    
    # Use existing volume (Secret, PVC, etc.)
    existingVolume:
      enabled: false
      volumeSource: {}
    
    # Or provide PEM content inline (creates Secret automatically)
    privateKey: ""
    publicKey: ""

  # Encryption (stored in Secret)
  encryption:
    key: "CHANGE_ME!"
    salt: "CHANGE_ME!"
    stateKey: "CHANGE_ME!"
    userIdHashSalt: "CHANGE_ME!"
```

#### MongoDB Configuration

```yaml
mongodb:
  host: "satosa-mongo"
  port: 27017                     # Number
  username: "satosa"
  password: "thatpassword"        # Stored in Secret

mongodbBackend:
  host: "satosa-mongo"
  port: 27017
  username: "satosa"
  password: "thatpassword"        # Stored in Secret
  database: "cie_oidc"
  collections:
    authentication: "cie_oidc_authentication"
    token: "cie_oidc_authentication_token"
    user: "cie_oidc_users"

mongodbFrontend:
  host: "satosa-mongo"
  port: 27017
  username: "satosa"
  password: "thatpassword"        # Stored in Secret
```

#### Organization & Contact Information

```yaml
organization:
  name:
    en: "example_organization"
    it: "example_organization"
  displayName:
    en: "Example Organization"
    it: "Example Organization"
  url:
    en: "https://example_organization.org"
    it: "https://example_organization.org/it"

contactPerson:
  emailAddress: "support.example@organization.org"
  telephoneNumber: "+3906123456789"
  fiscalCode: "XXXXXX00X00X000Y"
  givenName: "Contact Me"
  ipaCode: "ipa00c"
  municipality: "H501"
```

#### UI Configuration

```yaml
ui:
  description:
    en: "Resource description"
    it: "Resource description"
  displayName:
    en: "Resource Display Name"
    it: "Resource Display Name"
  informationUrl:
    en: "https://example_organization.org/information_url"
    it: "https://example_organization.org/it/information_url"
  privacyUrl:
    en: "https://example_organization.org/privacy"
    it: "https://example_organization.org/it/privacy"
  logo:
    url: "https://example_organization.org/logo.png"
    width: 80                     # Number
    height: 60                    # Number
```

#### PYEUDIW Configuration

```yaml
pyeudiw:
  # Leave empty to auto-generate from satosa.hostname
  federationClientId: ""
  x509ClientId: ""
```

### Other Standard Configurations

#### Image

```yaml
image:
  repository: ghcr.io/italia/iam-proxy-italia
  pullPolicy: IfNotPresent
  tag: ""  # Overrides chart appVersion
```

#### Service

```yaml
service:
  type: ClusterIP
  port: 80
```

#### Ingress

```yaml
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: iam.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: iam-proxy-tls
      hosts:
        - iam.example.com
```

#### Resources

```yaml
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

#### Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80
  targetMemoryUtilizationPercentage: 80
```

## Security Best Practices

### 1. Never Commit Secrets to Git

Create a separate values file for secrets and add it to `.gitignore`:

```bash
# values-production.yaml (add to .gitignore)
satosa:
  hostname: "iam.production.com"
  encryption:
    key: "actual-secure-key-here"
    # ... other secrets
```

### 2. Use Encrypted Secrets

#### With helm-secrets

```bash
# Install plugin
helm plugin install https://github.com/jkroepke/helm-secrets

# Create encrypted file
helm secrets enc values-secrets.yaml

# Deploy with encrypted values
helm secrets install myrelease ./charts/iam-proxy-italia \
  -f values.yaml \
  -f secrets://values-secrets.yaml
```

#### With Sealed Secrets

```bash
# Create sealed secret
kubectl create secret generic my-satosa-secret --dry-run=client -o yaml \
  --from-literal=satosa-encryption-key='my-key' | \
  kubeseal -o yaml > sealed-secret.yaml

# Apply sealed secret
kubectl apply -f sealed-secret.yaml

# Use in chart
helm install myrelease ./charts/iam-proxy-italia \
  --set secret.create=false \
  --set secret.existingSecret=my-satosa-secret
```

### 3. Use External Secret Management

#### External Secrets Operator

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: satosa-external-secret
spec:
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: my-satosa-secret
  data:
    - secretKey: satosa-encryption-key
      remoteRef:
        key: satosa/encryption-key
    # ... other secrets
```

Then:

```bash
helm install myrelease ./charts/iam-proxy-italia \
  --set secret.create=false \
  --set secret.existingSecret=my-satosa-secret
```

## Environment Variables Reference

All environment variables are automatically configured from values. Here's the mapping:

| Environment Variable | Values Path | Type | Stored in Secret |
|---------------------|-------------|------|------------------|
| `TZ` | `timezone` | string | No |
| `SATOSA_DEBUG` | `satosa.debug` | boolean → string | No |
| `SATOSA_HOSTNAME` | `satosa.hostname` | string | No |
| `SATOSA_ENCRYPTION_KEY` | `satosa.encryption.key` | string | **Yes** |
| `SATOSA_SALT` | `satosa.encryption.salt` | string | **Yes** |
| `SATOSA_STATE_ENCRYPTION_KEY` | `satosa.encryption.stateKey` | string | **Yes** |
| `SATOSA_USER_ID_HASH_SALT` | `satosa.encryption.userIdHashSalt` | string | **Yes** |
| `MONGODB_PASSWORD` | `mongodb.password` | string | **Yes** |
| `MONGODB_BACKEND_PASSWORD` | `mongodbBackend.password` | string | **Yes** |
| `MONGODB_FRONTEND_PASSWORD` | `mongodbFrontend.password` | string | **Yes** |

See the deployment template for the complete list of environment variables.

## Upgrading

### From values without secret management

If you're upgrading from a version that stored secrets directly in values:

1. **Option A**: Continue using auto-generated secrets (default behavior)
   - No changes needed
   - Your existing values will continue to work

2. **Option B**: Migrate to external secret
   - Create a Kubernetes Secret with your values
   - Update your values to use `secret.existingSecret`

```bash
# Backup current values
helm get values myrelease > backup-values.yaml

# Create secret from current values
kubectl create secret generic my-satosa-secret \
  --from-literal=satosa-encryption-key='...' \
  # ... other secrets

# Upgrade with existing secret
helm upgrade myrelease ./charts/iam-proxy-italia \
  -f backup-values.yaml \
  --set secret.create=false \
  --set secret.existingSecret=my-satosa-secret
```

## Troubleshooting

### Secret not found error

```
Error: secrets "xxx-secret" not found
```

**Solution**: Either enable secret creation or ensure your existing secret exists:

```bash
# Check if secret exists
kubectl get secret my-satosa-secret

# Or enable creation
helm upgrade myrelease ./charts/iam-proxy-italia --set secret.create=true
```

### Missing secret keys

```
Error: key "satosa-encryption-key" not found in secret
```

**Solution**: Ensure your existing secret contains all required keys (see "Required Secret Keys" section).

### Boolean values appearing as strings

This is expected behavior. The chart automatically converts boolean values (e.g., `true`, `false`) to strings (`"true"`, `"false"`) when passing them as environment variables.

## Contributing

Contributions are welcome! Please ensure:

1. All sensitive defaults are marked with "CHANGE_ME!"
2. New secret values are added to both `secret.yaml` template and documentation
3. Boolean values use native YAML booleans in values.yaml
4. Numbers use native YAML numbers in values.yaml

## License

See the main project repository for license information.
