"""
proton-relay — serves Proton Pass fields to in-cluster consumers over HTTP.

Targets pass-cli 2.4.x. Relevant upstream behaviour (verified against pass-cli source):
  * 2.4.0 refuses a session dir that is a symlink, and a `.session` dir with any
    group/other permission bits (fsGroup on a PVC does exactly that).
  * Proton refresh tokens rotate: concurrent pass-cli processes sharing one session
    can invalidate each other. All pass-cli calls are therefore serialized.
  * Field lookup mirrors pass-cli's own Item::get_field() (pass-domain/src/models/item/field.rs):
    case-insensitive, item-level custom fields first, Custom-item sections as
    "Section.field" with an unqualified fallback.
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
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("proton-relay")


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

# Item types this relay knows how to resolve. CreditCard, Wifi and Identity are
# deliberately unsupported: their data has no business in a Kubernetes Secret.
SUPPORTED_TYPES = {"Login", "Note", "Custom", "SshKey"}
ALLOWED_TYPES = {t.strip() for t in os.environ.get("ALLOWED_ITEM_TYPES", "Login,Note,Custom").split(",") if t.strip()}
if not ALLOWED_TYPES <= SUPPORTED_TYPES:
    log.error("ALLOWED_ITEM_TYPES contains unsupported types: %s (supported: %s)",
              sorted(ALLOWED_TYPES - SUPPORTED_TYPES), sorted(SUPPORTED_TYPES))
    sys.exit(1)

CACHE_TTL = float(os.environ.get("CACHE_TTL_SECONDS", "60"))          # 0 disables
CLI_TIMEOUT = float(os.environ.get("PASS_CLI_TIMEOUT_SECONDS", "60"))
LOCK_WAIT = float(os.environ.get("LOCK_WAIT_SECONDS", "90"))
MAX_REASON = 300  # pass/src/monitor.rs MAX_REASON_LENGTH

# Filesystem key storage — keyring/env providers mismatch in containers. Do not change.
os.environ["PROTON_PASS_KEY_PROVIDER"] = "fs"

log.info("Starting proton-relay | vault=%s | types=%s | cache_ttl=%ss", VAULT, sorted(ALLOWED_TYPES), CACHE_TTL)


# ── Session directory (pass-cli 2.4.x hardening) ─────────────────────────────

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


# ── pass-cli invocation ──────────────────────────────────────────────────────

_cli_lock = threading.Lock()   # one pass-cli process at a time: shared session, rotating refresh token
_state = {"ready": False}

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_TRACING = re.compile(r"^\d{4}-\d{2}-\d{2}T\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s")

NO_SESSION = "requires an authenticated client"
ITEM_MISSING = "No item found with title"
VAULT_MISSING = "Error finding vault"


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


def pass_cli(args: list[str], reason: str | None = None) -> tuple[int, str, str]:
    env = dict(os.environ, RUST_BACKTRACE="0")
    # Required for agent tokens, ignored for regular PATs (agent_monitor.rs). An operator-set value wins.
    if reason and "PROTON_PASS_AGENT_REASON" not in os.environ:
        env["PROTON_PASS_AGENT_REASON"] = reason[:MAX_REASON]
    try:
        r = subprocess.run(["pass-cli", *args], capture_output=True, text=True, env=env, timeout=CLI_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.error("pass-cli %s timed out after %ss", args[0], CLI_TIMEOUT)
        return 124, "", "timeout"
    err = condense(r.stderr)
    if r.returncode != 0:
        log.warning("pass-cli %s failed (exit %d): %s", args[0], r.returncode, err)
    return r.returncode, r.stdout, err


def session_valid() -> bool:
    return pass_cli(["info"])[0] == 0


def reauthenticate() -> bool:
    """Caller must hold _cli_lock."""
    log.info("Authenticating with PAT…")
    pass_cli(["logout", "--force"])
    ok = pass_cli(["login"])[0] == 0 and session_valid()
    _state["ready"] = ok
    log.info("Authentication %s", "succeeded" if ok else "FAILED")
    return ok


# ── Item fetch with cache ─────────────────────────────────────────────────────

_cache: dict[str, tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def _cache_get(title: str) -> dict | None:
    with _cache_lock:
        hit = _cache.get(title)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        _cache.pop(title, None)
        return None


def _view(title: str) -> tuple[int, str, str]:
    return pass_cli(
        ["item", "view", f"--vault-name={VAULT}", f"--item-title={title}", "--output", "json"],
        reason=f"proton-relay: read item '{title}' for Kubernetes secret sync",
    )


def get_item(title: str) -> dict:
    if CACHE_TTL > 0 and (item := _cache_get(title)) is not None:
        return item
    if not _cli_lock.acquire(timeout=LOCK_WAIT):
        raise HTTPException(503, "Relay busy, retry later")
    try:
        if CACHE_TTL > 0 and (item := _cache_get(title)) is not None:
            return item  # filled while we waited for the lock
        rc, out, err = _view(title)
        if rc != 0 and ITEM_MISSING not in err and VAULT_MISSING not in err and rc != 124:
            if NO_SESSION in err or not session_valid():
                log.warning("Session invalid — re-authenticating")
                if not reauthenticate():
                    raise HTTPException(503, "Failed to re-authenticate with Proton Pass")
                rc, out, err = _view(title)
        if rc != 0:
            if rc == 124:
                raise HTTPException(504, "pass-cli timed out")
            if ITEM_MISSING in err:
                raise HTTPException(404, f"Item not found: {title}")
            if VAULT_MISSING in err:
                log.error("Configured vault %r not found — check PROTON_PASS_VAULT", VAULT)
                raise HTTPException(500, "Configured vault not found")
            raise HTTPException(502, "pass-cli error")
        try:
            item = json.loads(out)["item"]
        except (ValueError, KeyError, TypeError):
            raise HTTPException(502, "Unparseable pass-cli output")
    finally:
        _cli_lock.release()

    kind = item_kind(item)
    if kind not in ALLOWED_TYPES:
        log.warning("Refused %s item '%s' (type not allowed)", kind, title)
        raise HTTPException(403, f"Item type {kind} is not served by this relay")
    if CACHE_TTL > 0:
        with _cache_lock:
            _cache[title] = (time.monotonic() + CACHE_TTL, item)
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
        if not reauthenticate():
            log.error("Initial authentication failed — exiting")
            sys.exit(1)
    log.info("=== proton-relay ready ===")
    yield


app = FastAPI(title="proton-relay", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
bearer = HTTPBearer()


def verify_token(creds: HTTPAuthorizationCredentials = Security(bearer)) -> None:
    if not hmac.compare_digest(creds.credentials.encode(), BRIDGE_TOKEN):
        raise HTTPException(401, "Unauthorized")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/ready")
def ready(response: Response):
    if not _state["ready"]:
        response.status_code = 503
    return {"ready": _state["ready"]}


@app.get("/secret/{item}/{field}", dependencies=[Depends(verify_token)])
def get_secret(item: str, field: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    value = get_field(item_fields(get_item(item)), field)
    if value is None:
        log.warning("Field '%s' not found in item '%s'", field, item)
        raise HTTPException(404, f"Field '{field}' not found in item '{item}'")
    log.info("Served %s/%s", item, field)
    return {"value": value}


@app.get("/fields/{item}", dependencies=[Depends(verify_token)])
def list_fields(item: str):
    data = get_item(item)
    names = list(dict.fromkeys(name for name, _ in item_fields(data)))
    return {"item": item, "type": item_kind(data), "fields": names}