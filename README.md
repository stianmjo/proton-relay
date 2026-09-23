# proton-relay

*A proton relay transfers energy between systems — this one transfers secrets between Proton Pass and Kubernetes.*

Bridges [External Secrets Operator](https://external-secrets.io) to [Proton Pass](https://proton.me/pass) vaults, using the Proton Pass CLI and a scoped Personal Access Token.

```
ExternalSecret → ESO → proton-relay → pass-cli → Proton Pass API → Kubernetes Secret
```

## Requirements

- Proton Pass **paid plan** (the CLI requires it)
- External Secrets Operator running in-cluster
- pass-cli 2.4.x in the image (tested with 2.4.1)

## Setup

**1. Vault** — create a vault in Proton Pass (e.g. `Kubernetes`); its name becomes `PROTON_PASS_VAULT`.

**2. PAT** — on your local machine:

```sh
pass-cli pat create --name "my-cluster-eso" --expiration 1y   # token is shown once — save it
pass-cli pat access grant --pat-name "my-cluster-eso" --vault-name "Kubernetes" --role viewer
```

**3. Secret** (applied manually — never committed):

```sh
read -rsp 'PAT: ' PAT; echo            # keeps the token out of shell history
kubectl create secret generic proton-relay -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" \
  --from-literal=BRIDGE_TOKEN="$(openssl rand -hex 32)"
unset PAT

kubectl label secret proton-relay -n external-secrets external-secrets.io/type=webhook
```

`deploy/secret.yaml.example` shows the expected shape. It is deliberately not a `.yaml` file, so `kubectl apply -f deploy/` can never overwrite the real Secret with placeholders.

**4. Deploy:**

```sh
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/eso-secretstore.yaml

kubectl logs -n external-secrets deploy/proton-relay
# Authentication succeeded → === proton-relay ready ===
```

## Adding secrets

Create items in the vault and use **hidden fields** for secret values. Reference them by `<ItemTitle>/<field>`:

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

A commented version with every field type is in `deploy/externalsecret.yaml.example`.

Keep item titles free of `/` and spaces — the title is a URL path segment.

### Item types

| Type | Served | Fields |
|---|---|---|
| Login | yes | `username` `password` `email` `urls` (comma-joined) `url` (first URL) `totp` / `totp_uri` |
| Custom | yes | `<Section>.<field>` for every section field |
| Note | yes | — |
| SSH key | opt-in (`ALLOWED_ITEM_TYPES`) | `private_key` `public_key` + section fields |
| Credit card, Wifi, Identity | **no** — `403` | — |

Every served item also has `title`, `note`, and any custom field you added to it by name.

### Lookup rules

Field lookup mirrors pass-cli's own resolver, so references behave the same as `pass://` references:

- Names are **case-insensitive**.
- Search order: `title`, `note`, the item's custom fields, then the type's fields. First match wins — a custom field named `password` shadows a Login's password.
- An exact match is tried first; otherwise the part after the last `.` is matched. `token` finds `API.token`; use `Zone.token` to pick a specific section.
- Empty built-in fields don't exist (`404`); an empty custom field returns `""`.
- TOTP fields return the `otpauth://` URI, not a code. Timestamp fields return Unix seconds.

Discover an item's exact field names:

```sh
curl -s -H "Authorization: Bearer <BRIDGE_TOKEN>" \
  http://proton-relay.external-secrets.svc:80/fields/<ItemTitle>
```

## API

| Endpoint | Auth | Response |
|---|---|---|
| `GET /health` | — | `200` always (liveness) |
| `GET /ready` | — | `200` while authenticated to Proton, `503` otherwise (readiness) |
| `GET /secret/{item}/{field}` | bearer | `{"value": "..."}` |
| `GET /fields/{item}` | bearer | `{"item": "...", "type": "...", "fields": [...]}` |

Errors: `401` bad bearer · `403` item type not served · `404` item or field not found · `500` configured vault not found · `502` pass-cli error · `503` re-authentication failed or relay busy · `504` pass-cli timed out.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | *required* | PAT from `pass-cli pat create` |
| `PROTON_PASS_VAULT` | *required* | Vault name the PAT can read |
| `BRIDGE_TOKEN` | *required* | Shared secret between ESO and the bridge |
| `ALLOWED_ITEM_TYPES` | `Login,Note,Custom` | Add `SshKey` to serve SSH keys. Other types are refused at startup |
| `CACHE_TTL_SECONDS` | `60` | Per-item cache; `0` disables |
| `PASS_CLI_TIMEOUT_SECONDS` | `60` | Max runtime of one pass-cli call |
| `LOCK_WAIT_SECONDS` | `90` | Max queue wait before `503` |
| `PROTON_PASS_SESSION_DIR` | `~/.local/share/proton-pass-cli` | pass-cli session location |
| `PROTON_PASS_AGENT_REASON` | per-request | Audit reason for agent tokens; ignored by regular PATs |
| `LOG_LEVEL` | `INFO` | |

## Operations

**Session directory.** The session is disposable — the relay logs out and back in on every start. `deploy/deployment.yaml` mounts an `emptyDir` at `/session` and points `PROTON_PASS_SESSION_DIR` at it. pass-cli 2.4+ refuses a symlinked session directory or one readable by group/others. The relay tightens permissions at startup and fails fast on symlinks, so never mount the session directory from a Secret or ConfigMap.

**Filesystem.** The container runs as uid 1000 with a read-only root filesystem. `/session` and `/tmp` (both `emptyDir`) are the only writable paths; anything new that needs to write gets its own `emptyDir`.

**Probes.** Liveness → `/health`, readiness → `/ready`.

**Throughput.** pass-cli calls run one at a time: concurrent processes on one session race Proton's rotating refresh token and sign each other out. Each uncached lookup lists and decrypts the whole vault, so keep the vault small and the cache on.

## PAT rotation

PATs expire — set a reminder ~2 weeks before. Grants are preserved across renewal.

```sh
pass-cli pat renew --pat-name "my-cluster-eso" --expiration 1y   # prints the new token

read -rsp 'New PAT: ' PAT; echo
kubectl patch secret proton-relay -n external-secrets --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN\",\"value\":\"$(printf %s "$PAT" | base64 -w0)\"}]"
unset PAT

kubectl rollout restart deploy/proton-relay -n external-secrets
```

## Security

- PAT is scoped to one vault with `viewer` (read-only) role — no other vaults reachable
- Credit card, Wifi and Identity items are never served, cached or logged
- Every request requires a valid `BRIDGE_TOKEN` bearer header (constant-time comparison)
- Secret values are never logged — only item titles and field names
- Responses carry `Cache-Control: no-store`; OpenAPI docs are disabled
- Values are held in memory for at most `CACHE_TTL_SECONDS`
- pass-cli uses filesystem key storage inside the container; Proton's E2E encryption is unaffected
- Pod runs as non-root (uid 1000) with a read-only root filesystem, all capabilities dropped, no privilege escalation, `RuntimeDefault` seccomp, and no service-account token

## Updating pass-cli

1. The scheduled `pass-cli-update` workflow opens a PR bumping `PASS_CLI_VERSION` and `PASS_CLI_HASH` in `bridge/Dockerfile`.
2. Click **Approve workflows to run** on the PR — the suite runs against the new binary.
3. Review the pass-cli changelog for breaking changes, then merge.
4. Tag and publish a release — patch bump for a pass-cli-only update, minor/major if relay behaviour changes. The release runs the tests again, then builds and pushes the image.

## Development

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests -q
```

The suite runs against a mock pass-cli and needs no PAT or network. Fixtures were generated from pass-cli 2.4.1's own data models, and lookups are checked against pass-cli's own resolver. Real-binary tests run when `pass-cli` is on `PATH` (or `PASS_CLI_REAL_BIN` is set), each in a throwaway session directory, so your personal session is never touched.

CI (`.github/workflows/tests.yaml`) runs the same suite on every pull request and before each release build, with the pass-cli version pinned in `bridge/Dockerfile`. Pull requests opened by the update workflow need **Approve workflows to run** once.
