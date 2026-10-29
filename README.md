# proton-relay

Serves secrets from a Proton Pass vault to [External Secrets Operator](https://external-secrets.io) (ESO), using the Proton Pass CLI and a read-only Personal Access Token (PAT).

```
ExternalSecret -> ESO -> proton-relay -> pass-cli -> Proton Pass -> Kubernetes Secret
```

## Requirements

- Proton Pass paid plan (the CLI requires it)
- External Secrets Operator in the cluster
- pass-cli 2.5.x (pinned in `bridge/Dockerfile`)

## Deploy

**1. Vault.** Create a vault in Proton Pass, for example `Kubernetes`.

**2. PAT.** On your own machine:

```sh
pass-cli pat create --name "my-cluster-eso" --expiration 1y     # shown once, save it
pass-cli pat access grant --pat-name "my-cluster-eso" --vault-name "Kubernetes" --role viewer
```

**3. Secret.** Apply by hand, never commit it:

```sh
read -rsp 'PAT: ' PAT; echo
kubectl create secret generic proton-relay -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" \
  --from-literal=BRIDGE_TOKEN="$(openssl rand -hex 32)"
unset PAT
kubectl label secret proton-relay -n external-secrets external-secrets.io/type=webhook
```

**4. Relay and store.** Set your vault name in `deploy/deployment.yaml` (`PROTON_PASS_VAULT`), then:

```sh
kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/eso-secretstore.yaml
kubectl logs -n external-secrets deploy/proton-relay     # expect: proton-relay ready | vault=...
```

## Using secrets

Reference a field as `<folder path>/<item title>/<field>`, or by item ID as `id:<ItemID>/<field>`.

| Key | Item |
|---|---|
| `postgres/password` | `postgres` at the vault root |
| `my-app/postgres/password` | `postgres` in folder `my-app` |
| `my-app/db/postgres/password` | `postgres` in folder `my-app/db` |
| `id:<ItemID>/password` | the item with that ID, in any folder |

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
  data:
    - secretKey: password
      remoteRef:
        key: "my-app/postgres/password"
```

More examples: `deploy/externalsecret.yaml.example`.

**Rules**

- Folder names and titles are exact and case-sensitive. Field names are case-insensitive.
- A key without a folder only matches items at the vault root.
- Keep folder names, titles and fields free of `/` and spaces. A root title can't start with `id:`.
- Trashed items are ignored.
- Two items with the same title in the same folder, or two sibling folders with the same name, return `409` with the matching IDs. Rename one or use `id:`.

**Item types**

| Type | Served | Fields |
|---|---|---|
| Login | yes | `username` `password` `email` `urls` `url` (first URL) `totp` `totp_uri` |
| Custom | yes | `<Section>.<field>`, or `<field>` if unique |
| Note | yes | none extra |
| SSH key | opt-in (`ALLOWED_ITEM_TYPES`) | `private_key` `public_key` + section fields |
| Credit card, Wifi, Identity | no (`403`) | |

Every served item also has `title`, `note` and its custom fields. Empty built-in fields return `404`. TOTP fields return the `otpauth://` URI.

**Find an item's ID and field names**

```sh
curl -s -H "Authorization: Bearer <BRIDGE_TOKEN>" \
  http://proton-relay.external-secrets.svc/fields/my-app/postgres
# {"item": "my-app/postgres", "id": "...", "type": "Login", "fields": ["title", "username", "password"]}
```

## API

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | none | `200` (liveness) |
| `GET /ready` | none | `200` after the first login (readiness) |
| `GET /secret/<key>/<field>` | bearer | `{"value": "..."}` |
| `GET /fields/<key>` | bearer | `{"item", "id", "type", "fields"}` |

| Code | Meaning |
|---|---|
| `400` | malformed key |
| `401` | wrong bearer token |
| `403` | item type not served |
| `404` | folder, item or field not found |
| `409` | ambiguous key |
| `500` | vault not found |
| `502` | pass-cli error |
| `503` | re-login failed, backing off, or relay busy |
| `504` | pass-cli timed out |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | required | PAT with viewer access to the vault |
| `PROTON_PASS_VAULT` | required | Vault name |
| `BRIDGE_TOKEN` | required | Bearer token shared with ESO |
| `ALLOWED_ITEM_TYPES` | `Login,Note,Custom` | Add `SshKey` to serve SSH keys |
| `CACHE_TTL_SECONDS` | `60` | Per-item cache, `0` disables |
| `PASS_CLI_TIMEOUT_SECONDS` | `60` | Max time for one pass-cli call |
| `LOCK_WAIT_SECONDS` | `90` | Max queue time before `503` |
| `LOGIN_BACKOFF_SECONDS` | `300` | Wait after a failed re-login before trying again |
| `PROTON_PASS_SESSION_DIR` | `~/.local/share/proton-pass-cli` | pass-cli session directory |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows pass-cli error details |

## Operations

**Sessions.** Proton sessions expire every few hours. The relay logs in again and retries the request once, so ESO never notices. If the login fails, requests get `503` and the relay waits `LOGIN_BACKOFF_SECONDS` before the next login, to stay under Proton's login rate limit.

**Readiness.** The pod is ready after its first login and stays ready. A pod that turned unready would be removed from the Service, and no request could reach it to trigger the login that fixes it.

**Logs.** One line per event. A healthy relay logs only `Served ...` and `Re-authenticated (...)`.

| Level | Meaning |
|---|---|
| `INFO` | normal operation |
| `WARNING` | a request was refused, fix the ExternalSecret or the vault |
| `ERROR` | the relay can't reach Proton Pass |

**Session directory.** Mount an `emptyDir` at `/session` (see `deploy/deployment.yaml`). pass-cli refuses symlinks and group/other permissions; the relay fixes permissions at startup. Never mount it from a Secret or ConfigMap.

**Throughput.** pass-cli calls run one at a time, since parallel calls on one session sign each other out. Keep the cache on.

## Security

- The PAT is read-only and scoped to one vault
- Credit card, Wifi and Identity items are refused before their contents are read
- Requested titles and folder names never reach the pass-cli command line
- Every request needs the bearer token (constant-time compare)
- Secret values are never logged
- Responses send `Cache-Control: no-store`; OpenAPI docs are off
- The pod runs as non-root with a read-only root filesystem, no capabilities and no service-account token

## PAT rotation

PATs expire. Renew about two weeks before:

```sh
pass-cli pat renew --pat-name "my-cluster-eso" --expiration 1y
read -rsp 'New PAT: ' PAT; echo
kubectl patch secret proton-relay -n external-secrets --type=json \
  -p="[{\"op\":\"replace\",\"path\":\"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN\",\"value\":\"$(printf %s "$PAT" | base64 -w0)\"}]"
unset PAT
kubectl rollout restart deploy/proton-relay -n external-secrets
```

## Updating pass-cli

1. The weekly `pass-cli-update` workflow opens a PR with the new version and hash.
2. Click **Approve workflows to run** so the tests run against the new binary.
3. Check the pass-cli changelog, then merge.
4. Publish a release (patch for a pass-cli-only update). The release runs the tests, then builds and pushes the image.

## Development

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests -q
```

The tests use a mock pass-cli with fixtures in `tests/fixtures/`, so they need no PAT or network. Tests against the real binary run when `pass-cli` 2.5+ is on `PATH` or `PASS_CLI_REAL_BIN` is set. CI runs the suite on every pull request and before every release.