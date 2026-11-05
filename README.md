# proton-relay

Serves secrets from a Proton Pass vault to [External Secrets Operator](https://external-secrets.io) (ESO).

```
ExternalSecret -> ESO -> proton-relay -> pass-cli -> Proton Pass
```

Needs a paid Proton Pass plan and ESO in the cluster.

## Install

**1. Create a vault** in Proton Pass, for example `Kubernetes`, and a read-only token for it:

```sh
pass-cli pat create --name "my-cluster-eso" --expiration 1y     # shown once, save it
pass-cli pat access grant --pat-name "my-cluster-eso" --vault-name "Kubernetes" --role viewer
```

**2. Create the Secret** (never commit it):

```sh
read -rsp 'PAT: ' PAT; echo
kubectl create secret generic proton-relay -n external-secrets \
  --from-literal=PROTON_PASS_PERSONAL_ACCESS_TOKEN="$PAT" \
  --from-literal=BRIDGE_TOKEN="$(openssl rand -hex 32)"
unset PAT
kubectl label secret proton-relay -n external-secrets external-secrets.io/type=webhook
```

**3. Deploy.** Set `PROTON_PASS_VAULT` in `deploy/deployment.yaml`, then:

```sh
kubectl apply -f deploy/deployment.yaml -f deploy/eso-secretstore.yaml
kubectl logs -n external-secrets deploy/proton-relay     # expect: proton-relay ready | vault=...
```

## Use

Reference a field as `<folder path>/<item title>/<field>`, or `id:<ItemID>/<field>`:

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
        key: "my-app/postgres/password"     # item "postgres" in folder "my-app"
```

- No folder means the vault root: `postgres/password`.
- Names are case-sensitive, field names are not. Avoid `/` and spaces in names.
- Two items or folders with the same name in the same place give `409`; use `id:` or rename one.
- Login, Note and Custom items are served. SSH keys need `ALLOWED_ITEM_TYPES=Login,Note,Custom,SshKey`.

To list an item's ID and fields:

```sh
curl -s -H "Authorization: Bearer <BRIDGE_TOKEN>" \
  http://proton-relay.external-secrets.svc/fields/my-app/postgres
```

More examples: `deploy/externalsecret.yaml.example`.

## Monitoring

Don't point a monitor at port 8080: that port also serves secrets. Add the health-only sidecar instead, and lock the relay down with NetworkPolicies:

```sh
kubectl apply -f deploy/health-proxy.yaml.example        # then add the sidecar, see the comments in the file
kubectl apply -f deploy/networkpolicy.yaml.example       # set your monitor's namespace and labels first
```

- Monitor URL: `http://proton-relay.external-secrets.svc:8081/health` (or `/ready`)
- 8080 accepts only the ESO controller, 8081 accepts only the monitor, and outbound traffic is DNS plus HTTPS to the internet.
- If the namespace has an allow-same-namespace policy, exclude `app: proton-relay` from it.

Check from the monitor pod: `:8081/health` returns `200`, and `proton-relay.external-secrets.svc:80` times out.

## Updating

- **pass-cli:** a weekly workflow opens a PR. Approve the workflow run, merge, then publish a patch release.
- **PAT:** renew about two weeks before it expires:

  ```sh
  pass-cli pat renew --pat-name "my-cluster-eso" --expiration 1y
  read -rsp 'New PAT: ' PAT; echo
  kubectl patch secret proton-relay -n external-secrets --type=json \
    -p="[{\"op\":\"replace\",\"path\":\"/data/PROTON_PASS_PERSONAL_ACCESS_TOKEN\",\"value\":\"$(printf %s "$PAT" | base64 -w0)\"}]"
  unset PAT
  kubectl rollout restart deploy/proton-relay -n external-secrets
  ```

<details>
<summary>Configuration</summary>

| Variable | Default | Description |
|---|---|---|
| `PROTON_PASS_PERSONAL_ACCESS_TOKEN` | required | PAT with viewer access to the vault |
| `PROTON_PASS_VAULT` | required | Vault name |
| `BRIDGE_TOKEN` | required | Bearer token shared with ESO |
| `ALLOWED_ITEM_TYPES` | `Login,Note,Custom` | Add `SshKey` to serve SSH keys |
| `CACHE_TTL_SECONDS` | `60` | Per-item cache, `0` disables |
| `PASS_CLI_TIMEOUT_SECONDS` | `60` | Max time for one pass-cli call |
| `LOCK_WAIT_SECONDS` | `90` | Max queue time before `503` |
| `LOGIN_BACKOFF_SECONDS` | `300` | Wait after a failed re-login |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows pass-cli error details |

</details>

<details>
<summary>API and status codes</summary>

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` | none | `200` (liveness) |
| `GET /ready` | none | `200` after the first login |
| `GET /secret/<key>/<field>` | bearer | `{"value": "..."}` |
| `GET /fields/<key>` | bearer | `{"item", "id", "type", "fields"}` |

`400` malformed key · `401` wrong token · `403` item type not served · `404` not found · `409` ambiguous key · `502` pass-cli error · `503` login failed or busy · `504` pass-cli timed out

</details>

<details>
<summary>Development</summary>

```sh
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests -q
```

The tests use a mock pass-cli (`tests/mock_pass_cli.py`, fixtures in `tests/fixtures/`), so they need no PAT or network. Tests against the real binary also run when `pass-cli` 2.5+ is on `PATH`.

</details>
