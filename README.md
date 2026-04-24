# proton-relay

A minimal HTTP bridge that lets [External Secrets Operator](https://external-secrets.io) pull secrets from [Proton Pass](https://proton.me/pass) using the [Proton Pass CLI](https://protonpass.github.io/pass-cli/) and a scoped Personal Access Token (PAT).

> **Why this exists**
> ESO has no native Proton Pass provider ([upstream issue #5689](https://github.com/external-secrets/external-secrets/issues/5689)). This bridge fills the gap using ESO's built-in [Webhook provider](https://external-secrets.io/latest/provider/webhook/), which can call any HTTP endpoint that returns JSON.

---

## How it works

```
ESO controller
  └─ ClusterSecretStore (webhook)
       └─ HTTP GET /secret/<item>/<field>   →   proton-relay
                                                  └─ pass-cli item view pass://Vault/Item/field
                                                       └─ Proton Pass API
```

1. ESO resolves an `ExternalSecret` and calls the bridge with `remoteRef.key` = `ItemTitle/fieldname`
2. The bridge prepends the configured vault name and calls `pass-cli item view`
3. The field value is returned as `{"value": "..."}` and ESO writes it into a Kubernetes `Secret`

---

## Prerequisites

- Proton Pass account on **Pass Plus, Pass Family, Pass Professional, or any Proton bundle** (CLI requires a paid plan)
- `pass-cli` installed locally to create the PAT
- External Secrets Operator installed in your cluster

---

## Setup

### 1. Create the PAT

On your local machine, logged in to `pass-cli`:

```sh
# Create a token valid for 1 year (maximum recommended for homelab)
pass-cli pat create --name "nebulahvelvet-eso" --expiration 1y
# Output:
# PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_xxxx...xxxx::TOKENKEY
#                                    ^^^ save this

# Grant the token read-only access to your secrets vault
pass-cli pat access grant \
  --pat-name "nebulahvelvet-eso" \
  --vault-name "Kubernetes" \
  --role viewer
```

> The PAT is scoped to a single vault with `viewer` (read-only) access.
> It cannot read any other vault, create, update, or delete anything.

### 2. Generate credentials

```sh
# Encryption key for pass-cli session storage inside the container
dd if=/dev/urandom bs=1 count=2048 2>/dev/null | sha256sum | awk '{print $1}'
# → use as PROTON_PASS_ENCRYPTION_KEY

# Shared secret between ESO and the bridge
dd if=/dev/urandom bs=1 count=2048 2>/dev/null | sha256sum | awk '{print $1}'
# → use as BRIDGE_TOKEN
```

### 3. Create the Kubernetes Secret

Edit `deploy/k8s/secret.yaml` with your values and apply:

```sh
kubectl apply -f deploy/k8s/secret.yaml
```

Or create it directly:

```sh
kubectl create secret generic proton-relay \
  -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_xxxx...xxxx::TOKENKEY" \
  --from-literal=PROTON_PASS_ENCRYPTION_KEY="<your-encryption-key>" \
  --from-literal=BRIDGE_TOKEN="<your-bridge-token>"
```

### 4. Deploy the bridge

```sh
kubectl apply -f deploy/k8s/deployment.yaml
```

Check it started correctly:

```sh
kubectl logs -n external-secrets deploy/proton-relay
# Authenticating pass-cli with PAT…
# pass-cli login successful
# INFO:     Started server process
# INFO:     Application startup complete.
```

### 5. Create the ClusterSecretStore

```sh
kubectl apply -f deploy/k8s/eso-secretstore.yaml
```

---

## Using it — ExternalSecret

`remoteRef.key` format: `<ItemTitle>/<fieldname>`

Standard field names: `password`, `username`, `email`, `url`, `note`
Custom field names: whatever you named them in Proton Pass

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: postgres-credentials
  namespace: default
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: protonpass
  target:
    name: postgres-credentials
    creationPolicy: Owner
  data:
    - secretKey: password
      remoteRef:
        key: "postgres/password"
    - secretKey: username
      remoteRef:
        key: "postgres/username"
```

This creates a Kubernetes `Secret` named `postgres-credentials` with keys `password` and `username` pulled from the item titled `postgres` in your `Kubernetes` vault.

---

## Configuration reference

| Environment variable | Required | Description |
|---|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | Yes | PAT from `pass-cli pat create` |
| `PROTON_PASS_ENCRYPTION_KEY` | Yes | Random key for pass-cli session encryption |
| `PROTON_PASS_VAULT` | Yes | Vault name the PAT has access to |
| `BRIDGE_TOKEN` | Yes | Shared secret for ESO → bridge authentication |

---

## PAT rotation

PATs have a mandatory expiration. With `1y` expiration, set a calendar reminder ~2 weeks before expiry.

To rotate:

```sh
# Renew the token (existing vault access grants are preserved automatically)
pass-cli pat renew --pat-name "nebulahvelvet-eso" --expiration 1y
# Output: PROTON_PASS_PERSONAL_ACCESS_TOKEN=pst_xxxx...xxxx::TOKENKEY (new value)

# Update the Kubernetes secret
kubectl patch secret proton-relay -n external-secrets \
  --type='json' \
  -p='[{"op":"replace","path":"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN","value":"'$(echo -n "pst_xxxx...xxxx::TOKENKEY" | base64)'"}]'

# Restart the bridge to pick up the new token
kubectl rollout restart deploy/proton-relay -n external-secrets
```

---

## Project structure

```
proton-relay/
├── bridge/
│   ├── app.py              # FastAPI bridge
│   ├── requirements.txt
│   └── Dockerfile
└── deploy/
    └── k8s/
        ├── secret.yaml         # Credentials (do not commit filled values)
        ├── deployment.yaml     # Deployment + Service
        └── eso-secretstore.yaml # ClusterSecretStore + ExternalSecret example
```

---

## Security notes

- The PAT is limited to `viewer` on a single vault — minimal blast radius if leaked
- The bridge only accepts requests with a valid `BRIDGE_TOKEN` bearer header
- The bridge never logs secret values, only item URIs
- `PROTON_PASS_ENCRYPTION_KEY` is used only for local session encryption inside the container — Proton's E2E encryption is unaffected