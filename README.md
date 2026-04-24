# proton-relay

> In Star Trek, a proton relay is a conduit that transfers energy between systems. This one transfers secrets between Proton Pass and your Kubernetes cluster.

A lightweight bridge that lets [External Secrets Operator](https://external-secrets.io) pull secrets from [Proton Pass](https://proton.me/pass) vaults into Kubernetes Secrets, using the Proton Pass CLI and a scoped Personal Access Token.

---

## How it works

```
ExternalSecret → ESO → proton-relay → pass-cli → Proton Pass API → Kubernetes Secret
```

ESO calls the bridge with an item/field reference. The bridge fetches it from Proton Pass via `pass-cli` and returns the value. ESO writes it into a Kubernetes Secret.

---

## Requirements

- Proton Pass **paid plan** (Pass Plus, Family, Professional, or any Proton bundle) — the CLI requires it
- `pass-cli` installed locally
- External Secrets Operator running in your cluster

---

## Setup

### 1. Create a vault in Proton Pass

Create a vault named `Kubernetes` (or whatever you prefer — you'll set it as `PROTON_PASS_VAULT` later).

### 2. Create a PAT

On your local machine:

```sh
# Create a token valid for 1 year
pass-cli pat create --name "my-cluster-eso" --expiration 1y
# Save the output token — you only see it once

# Grant it read-only access to your vault
pass-cli pat access grant \
  --pat-name "my-cluster-eso" \
  --vault-name "Kubernetes" \
  --role viewer
```

### 3. Generate a random bridge token

```sh
dd if=/dev/urandom bs=1 count=2048 2>/dev/null | sha256sum | awk '{print $1}'
# → use as BRIDGE_TOKEN
```

### 4. Create the Kubernetes secret

```sh
kubectl create secret generic proton-relay \
  -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_xxxx...xxxx::TOKENKEY" \
  --from-literal=BRIDGE_TOKEN="<your-bridge-token>"

kubectl label secret proton-relay -n external-secrets external-secrets.io/type=webhook
```

### 5. Deploy

```sh
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/eso-secretstore.yaml
```

Verify:

```sh
kubectl logs -n external-secrets deploy/proton-relay
# pass-cli login successful
# Application startup complete.
```

---

## Adding secrets

Create items in your `Kubernetes` vault in Proton Pass. Use **hidden fields** for secret values — you can add as many as you need per item.

Example: an item titled `postgres` with hidden fields `username` and `password`.

Reference them in an ExternalSecret:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: postgres
  namespace: my-app
spec:
  refreshInterval: 1h
  secretStoreRef:
    kind: ClusterSecretStore
    name: proton-relay
  target:
    name: postgres
    creationPolicy: Owner
  data:
    - secretKey: username
      remoteRef:
        key: "postgres/username"
    - secretKey: password
      remoteRef:
        key: "postgres/password"
```

`remoteRef.key` format: `<ItemTitle>/<fieldname>`

### Supported field types

| Field | Description |
|---|---|
| `title` | Item title |
| `note` | Item note |
| `username` `password` `email` `url` `totp` | Login item standard fields |
| `cardholder_name` `number` `expiration_date` `verif_number` `pin` | Credit card fields |
| `ssid` `password` | Wifi fields |
| Any custom name | Hidden or text extra fields |

### Discover available fields

Not sure what fields an item has? Hit the discovery endpoint:

```sh
curl -s -H "Authorization: Bearer <BRIDGE_TOKEN>" \
  http://proton-relay.external-secrets.svc:80/fields/<ItemTitle>
```

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | Yes | PAT from `pass-cli pat create` |
| `PROTON_PASS_VAULT` | Yes | Vault name the PAT has access to |
| `BRIDGE_TOKEN` | Yes | Shared secret between ESO and the bridge |

---

## PAT rotation

PATs expire — with `1y` set a calendar reminder ~2 weeks before expiry.

```sh
# Renew (vault access grants are preserved automatically)
pass-cli pat renew --pat-name "my-cluster-eso" --expiration 1y
# Save the new token value

# Update the secret
kubectl patch secret proton-relay -n external-secrets \
  --type='json' \
  -p='[{"op":"replace","path":"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN","value":"'$(echo -n "pst_xxxx...xxxx::TOKENKEY" | base64)'"}]'

# Restart to pick up the new token
kubectl rollout restart deploy/proton-relay -n external-secrets
```

---

## Security

- PAT is scoped to a single vault with `viewer` role — read-only, no other vaults accessible
- Every request to the bridge requires a valid `BRIDGE_TOKEN` bearer header
- Secret values are never logged — only item URIs appear in logs
- Session encryption is handled internally by pass-cli using filesystem key storage — Proton's E2E encryption is unaffected
