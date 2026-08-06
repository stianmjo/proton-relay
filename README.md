# proton-relay

*A proton relay transfers energy between systems — this one transfers secrets between Proton Pass and Kubernetes.*

Bridges [External Secrets Operator](https://external-secrets.io) to [Proton Pass](https://proton.me/pass) vaults, using the Proton Pass CLI and a scoped Personal Access Token.

```
ExternalSecret → ESO → proton-relay → pass-cli → Proton Pass API → Kubernetes Secret
```

## Requirements

- Proton Pass **paid plan** (the CLI requires it)
- External Secrets Operator running in-cluster

## Setup

**1. Vault** — create a vault in Proton Pass (e.g. `Kubernetes`); its name becomes `PROTON_PASS_VAULT`.

**2. PAT** — on your local machine:

```sh
pass-cli pat create --name "my-cluster-eso" --expiration 1y   # token is shown once — save it
pass-cli pat access grant --pat-name "my-cluster-eso" --vault-name "Kubernetes" --role viewer
```

**3. Bridge token:**

```sh
openssl rand -hex 32   # → BRIDGE_TOKEN
```

**4. Secret** (applied manually — never committed):

```sh
kubectl create secret generic proton-relay -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="pst_xxxx...xxxx::TOKENKEY" \
  --from-literal=BRIDGE_TOKEN="<your-bridge-token>"

kubectl label secret proton-relay -n external-secrets external-secrets.io/type=webhook
```

**5. Deploy:**

```sh
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/eso-secretstore.yaml

kubectl logs -n external-secrets deploy/proton-relay
# Login successful → === proton-relay ready ===
```

## Adding secrets

Create items in the vault and use **hidden fields** for secret values. Reference them by `<ItemTitle>/<fieldname>`:

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

**Fields:** `title`, `note`; Login (`username` `password` `email` `url` `totp`); Credit card (`cardholder_name` `number` `expiration_date` `verif_number` `pin`); Wifi (`ssid` `password`); or any custom hidden/text field by its name.

Discover an item's fields:

```sh
curl -s -H "Authorization: Bearer <BRIDGE_TOKEN>" \
  http://proton-relay.external-secrets.svc:80/fields/<ItemTitle>
```

## Environment variables

| Variable | Description |
|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | PAT from `pass-cli pat create` |
| `PROTON_PASS_VAULT` | Vault name the PAT can read |
| `BRIDGE_TOKEN` | Shared secret between ESO and the bridge |

## PAT rotation

PATs expire — set a reminder ~2 weeks before. Grants are preserved across renewal.

```sh
pass-cli pat renew --pat-name "my-cluster-eso" --expiration 1y   # save the new token value

kubectl patch secret proton-relay -n external-secrets --type='json' \
  -p='[{"op":"replace","path":"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN","value":"'$(echo -n "pst_xxxx...xxxx::TOKENKEY" | base64 -w0)'"}]'

kubectl rollout restart deploy/proton-relay -n external-secrets
```

## Security

- PAT is scoped to one vault with `viewer` (read-only) role — no other vaults reachable
- Every bridge request requires a valid `BRIDGE_TOKEN` bearer header
- Secret values are never logged — only item URIs appear in logs
- pass-cli uses filesystem key storage inside the container; Proton's E2E encryption is unaffected