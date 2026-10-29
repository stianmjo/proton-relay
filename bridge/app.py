"""
proton-relay — serves Proton Pass fields to in-cluster consumers (External Secrets Operator) over HTTP.

Key format (everything after /secret/ or /fields/):
    <folder>/.../<ItemTitle>/<field>    the item at exactly that folder path (no folder = vault root)
    id:<ItemID>/<field>                 the item with that Proton ID, wherever it is in the vault
Folder names and titles match exactly. Field names are case-insensitive. Trashed items are ignored.
If two items (or two sibling folders) share a name, the key is ambiguous: 409, never a guess.

Targets pass-cli 2.5.x. Upstream behaviour relied on (verified against pass-cli source):
  * `item list --output json` prints metadata only (id, title, folder_id, item_type, state), never secrets.
  * `folder list --output json` prints [{id, parent_folder_id, content: {name}}].
  * 2.4.0+ refuses a session dir that is a symlink or has group/other permission bits.
  * Proton refresh tokens rotate: concurrent pass-cli processes on one session sign each other out,
    so all pass-cli calls are serialized.
  * Field lookup mirrors pass-cli's own Item::get_field() (pass/src/domain/models/item/field.rs).
"""

import hmac
import json
import logging
import os
import re
import stat
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ── Logging ───────────────────────────────────────────────────────────────────
# INFO: normal operation (served, re-authenticated). WARNING: a request we refused (404/409/403).
# ERROR: needs attention (login failing, pass-cli failing after re-login). pass-cli error chains: DEBUG.

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("proton-relay")


class _ProbeAccessFilter(logging.Filter):
    """Drop uvicorn access-log lines for successful /health and /ready probes; failed probes still log."""

    PATHS = frozenset({"/health", "/ready"})

    def filter(self, record: logging.LogRecord) -> bool:
        # uvicorn logs: '%s - "%s %s HTTP/%s" %d' % (client, method, path, http_version, status)
        args = record.args
        if isinstance(args, tuple) and len(args) == 5:
            path, status = args[2], args[4]
            if path in self.PATHS and isinstance(status, int) and status < 400:
                return False
        return True


# uvicorn configures its loggers before importing this module, so the filter survives startup.
logging.getLogger("uvicorn.access").addFilter(_ProbeAccessFilter())


# ── Config ────────────────────────────────────────────────────────────────────

def _require(name: str) -> str:
    value = os.environ.get(name, "")
    if not value.strip():
        log.error("Required environment variable %s is missing or empty", name)
        sys.exit(1)
    return value


# pass-cli reads the PAT from the environment itself; we only enforce its presence.
_require("PROTON_PASS_PERSONAL_ACCESS_TOKEN")
VAULT = _require("PROTON_PASS_VAULT")
BRIDGE_TOKEN = _require("BRIDGE_TOKEN").encode()

# Item types this relay can serve. CreditCard, Wifi and Identity are deliberately unsupported:
# their data has no business in a Kubernetes Secret.
SUPPORTED_TYPES = {"Login", "Note", "Custom", "SshKey"}
ALLOWED_TYPES = {t.strip() for t in os.environ.get("ALLOWED_ITEM_TYPES", "Login,Note,Custom").split(",") if t.strip()}
if not ALLOWED_TYPES <= SUPPORTED_TYPES:
    log.error("ALLOWED_ITEM_TYPES contains unsupported types: %s (supported: %s)",
              sorted(ALLOWED_TYPES - SUPPORTED_TYPES), sorted(SUPPORTED_TYPES))
    sys.exit(1)

# `item list` reports types in snake_case; the relay (and ALLOWED_ITEM_TYPES) uses pass-cli's JSON names.
LIST_TYPES = {"login": "Login", "note": "Note", "custom": "Custom", "ssh_key": "SshKey", "alias": "Alias",
              "credit_card": "CreditCard", "identity": "Identity", "wifi": "Wifi"}

CACHE_TTL = float(os.environ.get("CACHE_TTL_SECONDS", "60"))           # 0 disables
CLI_TIMEOUT = float(os.environ.get("PASS_CLI_TIMEOUT_SECONDS", "60"))  # per pass-cli call
LOCK_WAIT = float(os.environ.get("LOCK_WAIT_SECONDS", "90"))
# After a failed re-login, wait this long before trying again: repeated logins trip Proton's
# per-account rate limit (API code 2028), which pass-cli reports only as free text.
LOGIN_BACKOFF = float(os.environ.get("LOGIN_BACKOFF_SECONDS", "300"))
MAX_REASON = 300  # pass-cli monitor.rs MAX_REASON_LENGTH

# Filesystem key storage — keyring/env providers mismatch in containers. Do not change.
os.environ["PROTON_PASS_KEY_PROVIDER"] = "fs"


# ── Session directory (pass-cli 2.4+ hardening) ──────────────────────────────

def session_base_dir() -> Path:
    """Same resolution as pass-cli utils.rs get_base_dir() on Linux."""
    if custom := os.environ.get("PROTON_PASS_SESSION_DIR"):
        return Path(custom)
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "proton-pass-cli"


def prepare_session_dir() -> None:
    base = session_base_dir()
    if base.is_symlink():
        raise RuntimeError(f"Session dir {base} is a symlink; pass-cli 2.4+ refuses it. "
                           "Point PROTON_PASS_SESSION_DIR at a real directory (e.g. an emptyDir).")
    sess = base / ".session"
    try:
        st = sess.lstat()
    except FileNotFoundError:
        return  # pass-cli creates it 0700 itself
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{sess} is not a real directory; pass-cli 2.4+ refuses it.")
    if st.st_mode & 0o077:
        mode = stat.S_IMODE(st.st_mode)
        log.warning("%s is mode %o (group/other access, typically fsGroup on a volume); "
                    "tightening to %o — pass-cli 2.4+ refuses it otherwise", sess, mode, mode & ~0o077)
        os.chmod(sess, mode & ~0o077)


# ── pass-cli ──────────────────────────────────────────────────────────────────

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TRACING = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s")

NO_SESSION = "requires an authenticated client"
# The only pass-cli failure that means "your config is wrong". Anything else (expired session, a refresh
# pass-cli failed to persist: "Error finding vault [..]: Error listing vaults") is a broken session.
VAULT_MISSING = "Could not find vault"


class CliError(Exception):
    """A pass-cli call failed. `detail` is condensed stderr (pass-cli never prints secret values there)."""

    def __init__(self, detail: str, timed_out: bool = False):
        super().__init__(detail)
        self.detail, self.timed_out = detail, timed_out

    @property
    def short(self) -> str:
        """Last link of the error chain, e.g. 'non-existent session'."""
        return re.sub(r"^(\d+: |Error: )", "", self.detail.rsplit(" | ", 1)[-1])


def condense(stderr: str) -> str:
    """Keep pass-cli's error + cause chain; drop ANSI, tracing lines and backtraces."""
    out = []
    for line in _ANSI.sub("", stderr or "").splitlines():
        if line.startswith("Stack backtrace"):
            break
        line = line.strip()
        if line and not _TRACING.match(line):
            out.append(line)
    return " | ".join(out)[:600]


def pass_cli(args: list[str], reason: str | None = None) -> str:
    """Run pass-cli and return stdout. Raises CliError on failure or timeout."""
    env = dict(os.environ, RUST_BACKTRACE="0")
    # Required for agent tokens, ignored for regular PATs. An operator-set value wins.
    if reason and "PROTON_PASS_AGENT_REASON" not in os.environ:
        env["PROTON_PASS_AGENT_REASON"] = reason[:MAX_REASON]
    cmd = " ".join(a for a in args[:2] if not a.startswith("-"))
    try:
        r = subprocess.run(["pass-cli", *args], capture_output=True, text=True, env=env, timeout=CLI_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise CliError(f"pass-cli {cmd} timed out after {CLI_TIMEOUT:g}s", timed_out=True)
    if r.returncode != 0:
        err = condense(r.stderr)
        log.debug("pass-cli %s failed (exit %d): %s", cmd, r.returncode, err)
        raise CliError(err)
    return r.stdout


def pass_cli_json(args: list[str], reason: str):
    try:
        return json.loads(pass_cli([*args, f"--vault-name={VAULT}", "--output=json"], reason))
    except ValueError:
        raise HTTPException(502, "Unparseable pass-cli output")


# ── Session ───────────────────────────────────────────────────────────────────

_cli_lock = threading.Lock()   # one pass-cli process at a time (shared session, rotating refresh token)
_state = {"login_after": 0.0}  # monotonic time before which no new login is attempted


def login() -> str | None:
    """Log in fresh with the PAT. Caller holds _cli_lock. Returns None on success, else why it failed."""
    wait = _state["login_after"] - time.monotonic()
    if wait > 0:
        return f"previous login failed, next attempt in {wait:.0f}s"
    try:
        pass_cli(["logout", "--force"])
    except CliError:
        pass  # nothing to log out of
    try:
        pass_cli(["login"])
        pass_cli(["info"])
    except CliError as e:
        _state["login_after"] = time.monotonic() + LOGIN_BACKOFF
        return e.detail
    _state["login_after"] = 0.0
    return None


# ── Keys ──────────────────────────────────────────────────────────────────────

KEY_HELP = "key must be <folder>/.../<item>/<field> or id:<ItemID>/<field>"


@dataclass(frozen=True)
class Ref:
    """Which item a key points at: a folder path + title, or a Proton item ID."""
    folders: tuple[str, ...] = ()
    title: str = ""
    item_id: str = ""

    def __str__(self) -> str:
        return f"id:{self.item_id}" if self.item_id else "/".join((*self.folders, self.title))


def parse_key(key: str, with_field: bool) -> tuple[Ref, str | None]:
    parts = key.split("/")
    field = parts.pop() if with_field and len(parts) > 1 else None
    if "" in parts or (with_field and not field):
        raise HTTPException(400, KEY_HELP)
    if parts[0].startswith("id:"):
        if len(parts) > 1 or parts[0] == "id:":
            raise HTTPException(400, KEY_HELP)
        return Ref(item_id=parts[0][3:]), field
    return Ref(folders=tuple(parts[:-1]), title=parts[-1]), field


# ── Item lookup ───────────────────────────────────────────────────────────────

def find_folder(path: tuple[str, ...], reason: str) -> str:
    """Folder ID for a folder path, walked from the vault root."""
    folders = pass_cli_json(["folder", "list"], reason)
    parent = None
    for depth, name in enumerate(path, 1):
        here = [f for f in folders if f["content"]["name"] == name and f.get("parent_folder_id") == parent]
        where = "/".join(path[:depth])
        if not here:
            raise HTTPException(404, f"Folder not found: {where}")
        if len(here) > 1:
            raise HTTPException(409, f"Ambiguous folder: {len(here)} folders at {where}")
        parent = here[0]["id"]
    return parent


def fetch_item(ref: Ref) -> dict:
    """Resolve ref to exactly one active item via metadata, then read that one item by ID."""
    try:
        return _fetch_item(ref)
    except (KeyError, TypeError, AttributeError):   # pass-cli JSON not shaped as expected
        raise HTTPException(502, "Unexpected pass-cli output")


def _fetch_item(ref: Ref) -> dict:
    reason = f"proton-relay: read '{ref}' for Kubernetes secret sync"
    items = pass_cli_json(["item", "list", "--filter-state=active"], reason)["items"]
    if ref.item_id:
        matches = [i for i in items if i["id"] == ref.item_id]
    else:
        folder_id = find_folder(ref.folders, reason) if ref.folders else None
        matches = [i for i in items if i["title"] == ref.title and i.get("folder_id") == folder_id]

    if not matches:
        raise HTTPException(404, f"Item not found: {ref}")
    if len(matches) > 1:
        ids = ", ".join(f"id:{i['id']}" for i in matches)
        raise HTTPException(409, f"Ambiguous: {len(matches)} items match {ref}; use one of {ids}")
    kind = LIST_TYPES.get(matches[0]["item_type"], matches[0]["item_type"])
    if kind not in ALLOWED_TYPES:   # refused before its content is ever read
        raise HTTPException(403, f"Item type {kind} is not served by this relay")

    item = pass_cli_json(["item", "view", f"--item-id={matches[0]['id']}"], reason)["item"]
    if not isinstance(item, dict):
        raise TypeError("item is not an object")
    return item


def http_error(e: CliError) -> HTTPException:
    if e.timed_out:
        return HTTPException(504, "pass-cli timed out")
    if VAULT_MISSING in e.detail:
        log.error("Vault %r not found — check PROTON_PASS_VAULT", VAULT)
        return HTTPException(500, "Configured vault not found")
    return HTTPException(502, "pass-cli error")


_cache: dict[Ref, tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def _cache_get(ref: Ref) -> dict | None:
    with _cache_lock:
        hit = _cache.get(ref)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        _cache.pop(ref, None)
        return None


def get_item(ref: Ref) -> dict:
    """Cached fetch_item. A failing session gets one fresh login and one retry."""
    if CACHE_TTL > 0 and (item := _cache_get(ref)) is not None:
        return item
    if not _cli_lock.acquire(timeout=LOCK_WAIT):
        raise HTTPException(503, "Relay busy, retry later")
    try:
        if CACHE_TTL > 0 and (item := _cache_get(ref)) is not None:
            return item  # filled while we waited for the lock
        try:
            item = fetch_item(ref)
        except CliError as e:
            if e.timed_out or VAULT_MISSING in e.detail:
                raise http_error(e)
            # Expired or broken session. Don't gate this on `pass-cli info`: a session whose refresh
            # was never persisted still passes `info` while every API call fails.
            if failed := login():
                log.error("Session lost (%s); re-login failed: %s", e.short, failed)
                raise HTTPException(503, "Failed to re-authenticate with Proton Pass")
            try:
                item = fetch_item(ref)
            except CliError as e2:
                log.error("pass-cli still failing after re-login: %s", e2.detail)
                raise http_error(e2)
            log.info("Re-authenticated (%s)", e.short)
    finally:
        _cli_lock.release()
    if CACHE_TTL > 0:
        with _cache_lock:
            _cache[ref] = (time.monotonic() + CACHE_TTL, item)
    return item


# ── Field resolution (parity with pass-cli Item::fields / get_field) ─────────

def item_kind(item: dict) -> str:
    content = (item.get("content") or {}).get("content") or {}
    return next(iter(content), "Unknown") if isinstance(content, dict) else "Unknown"


def _extra_value(content: dict) -> str | None:
    # ItemExtraFieldContent: {"Text"|"Hidden"|"Totp": str} | {"Timestamp": i64}
    for key in ("Text", "Hidden", "Totp", "Timestamp"):
        if key in content:
            return str(content[key])
    return None


def _named(fields_in: list, prefix: str = "") -> list[tuple[str, str]]:
    out = []
    for f in fields_in or []:
        value = _extra_value(f.get("content") or {})
        if value is not None:
            out.append((f"{prefix}{f.get('name', '')}", value))
    return out


def _sections(sections: list) -> list[tuple[str, str]]:
    out = []
    for s in sections or []:
        out += _named(s.get("section_fields"), prefix=f"{s.get('section_name', '')}.")
    return out


def item_fields(item: dict) -> list[tuple[str, str]]:
    data = item.get("content") or {}
    kind = item_kind(item)
    body = (data.get("content") or {}).get(kind) or {}
    fields = []
    if data.get("title"):
        fields.append(("title", data["title"]))
    if data.get("note"):
        fields.append(("note", data["note"]))
    fields += _named(data.get("extra_fields"))
    if kind == "Login":
        fields += [(k, body[k]) for k in ("email", "username", "password") if body.get(k)]
        if body.get("totp_uri"):
            fields += [("totp", body["totp_uri"]), ("totp_uri", body["totp_uri"])]
        if body.get("urls"):
            fields.append(("urls", ", ".join(body["urls"])))
            fields.append(("url", body["urls"][0]))  # relay alias kept for existing consumers; never shadows
    elif kind == "SshKey":
        for key in ("private_key", "public_key"):
            if body.get(key):
                fields += [(key, body[key]), (key.replace("_", " "), body[key])]
        fields += _sections(body.get("sections"))
    elif kind == "Custom":
        fields += _sections(body.get("sections"))
    return fields


def get_field(fields: list[tuple[str, str]], query: str) -> str | None:
    q = query.lower()
    for name, value in fields:                      # exact (supports "Section.field")
        if name.lower() == q:
            return value
    for name, value in fields:                      # unqualified: part after the last '.'
        if name.rsplit(".", 1)[-1].lower() == q:
            return value
    return None


# ── App ───────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        prepare_session_dir()
    except (RuntimeError, OSError) as e:
        log.error("Session directory unusable: %s", e)
        sys.exit(1)
    with _cli_lock:
        if failed := login():
            log.error("Login to Proton Pass failed: %s — exiting", failed)
            sys.exit(1)
    log.info("proton-relay ready | vault=%s | types=%s | cache_ttl=%ss", VAULT, sorted(ALLOWED_TYPES), CACHE_TTL)
    yield


app = FastAPI(title="proton-relay", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
bearer = HTTPBearer()


def verify_token(creds: HTTPAuthorizationCredentials = Security(bearer)) -> None:
    if not hmac.compare_digest(creds.credentials.encode(), BRIDGE_TOKEN):
        raise HTTPException(401, "Unauthorized")


def lookup(key: str, with_field: bool) -> tuple[Ref, str | None, dict]:
    """Parse + fetch, logging refused requests once at WARNING."""
    try:
        ref, field = parse_key(key, with_field)
        return ref, field, get_item(ref)
    except HTTPException as e:
        if e.status_code < 500:
            log.warning("Refused %s: %s", key, e.detail)
        raise


@app.get("/health")
def health():
    return {"status": "ok"}


# Ready = the startup login succeeded (uvicorn serves nothing before that). Deliberately NOT "session healthy":
# an unready pod is dropped from the Service, so with one replica no request would ever arrive to trigger
# the re-login that heals it. A broken session is handled per request instead (re-login, 503, backoff).
@app.get("/ready")
def ready():
    return {"ready": True}


@app.get("/secret/{key:path}", dependencies=[Depends(verify_token)])
def get_secret(key: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    ref, field, item = lookup(key, with_field=True)
    value = get_field(item_fields(item), field)
    if value is None:
        log.warning("Refused %s: field not found", key)
        raise HTTPException(404, f"Field '{field}' not found in {ref}")
    log.info("Served %s", key)
    return {"value": value}


@app.get("/fields/{key:path}", dependencies=[Depends(verify_token)])
def list_fields(key: str):
    ref, _, item = lookup(key, with_field=False)
    names = list(dict.fromkeys(name for name, _ in item_fields(item)))
    return {"item": str(ref), "id": item.get("id"), "type": item_kind(item), "fields": names}