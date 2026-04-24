import json
import logging
import os
import subprocess
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

PAT          = os.environ["PROTON_PASS_PERSONAL_ACCESS_TOKEN"]
ENC_KEY      = os.environ["PROTON_PASS_ENCRYPTION_KEY"]
VAULT        = os.environ["PROTON_PASS_VAULT"]
BRIDGE_TOKEN = os.environ["BRIDGE_TOKEN"]

log.info("Starting proton-relay")
log.info("Vault: %s", VAULT)
log.info("Key provider: %s", os.environ.get("PROTON_PASS_KEY_PROVIDER", "NOT SET — setting now"))

# Ensure pass-cli uses env-based key storage for all subprocesses
os.environ["PROTON_PASS_KEY_PROVIDER"]   = "env"
os.environ["PROTON_PASS_ENCRYPTION_KEY"] = ENC_KEY

log.info("PROTON_PASS_KEY_PROVIDER set to: %s", os.environ["PROTON_PASS_KEY_PROVIDER"])

# ── Session management ────────────────────────────────────────────────────────

def run(args: list) -> subprocess.CompletedProcess:
    """Run a pass-cli command and log the result."""
    cmd = ["pass-cli"] + args
    log.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        log.warning("pass-cli %s failed (exit %d):\n%s", args[0], result.returncode, result.stderr.strip())
    return result


def session_valid() -> bool:
    """Use pass-cli test to check if the current session is valid."""
    log.info("Checking session validity (pass-cli test)…")
    result = run(["test"])
    if result.returncode == 0:
        log.info("Session is valid")
        return True
    log.warning("Session invalid: %s", result.stderr.strip())
    return False


def login() -> bool:
    """Login with PAT. Returns True on success."""
    log.info("Authenticating with PAT…")
    result = run(["login"])
    if result.returncode != 0:
        log.error("Login failed: %s", result.stderr.strip())
        return False
    log.info("Login successful: %s", result.stdout.strip())
    return True


def ensure_session() -> bool:
    """
    Verify session with pass-cli test.
    If invalid, force logout to clear stale data and re-login.
    """
    if session_valid():
        return True
    log.warning("Session invalid — clearing stale session and re-authenticating…")
    run(["logout", "--force"])
    return login()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("=== proton-relay startup ===")
    # Clear any stale session from a previous pod and login fresh
    log.info("Clearing any existing session before login…")
    run(["logout", "--force"])
    if not login():
        log.error("Initial login failed — exiting")
        sys.exit(1)
    # Verify immediately after login
    if not session_valid():
        log.error("Session invalid immediately after login — exiting")
        sys.exit(1)
    log.info("=== proton-relay ready ===")
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="proton-relay", lifespan=lifespan)
bearer = HTTPBearer()


def verify_token(creds: HTTPAuthorizationCredentials = Security(bearer)):
    if creds.credentials != BRIDGE_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── pass-cli wrapper ──────────────────────────────────────────────────────────

def get_item_json(item: str) -> dict:
    """
    Fetch full item JSON from Proton Pass.
    On session failure: re-authenticate via pass-cli test and retry once.
    """
    uri = f"pass://{VAULT}/{item}"
    log.info("Fetching item: %s", uri)

    result = run(["item", "view", uri, "--output", "json"])

    if result.returncode != 0:
        log.warning("Item fetch failed — checking session…")
        if not session_valid():
            log.warning("Session expired — re-authenticating…")
            run(["logout", "--force"])
            if not login():
                log.error("Re-authentication failed")
                raise HTTPException(status_code=503, detail="Failed to re-authenticate with Proton Pass")
            log.info("Re-authenticated — retrying item fetch…")
            result = run(["item", "view", uri, "--output", "json"])
            if result.returncode != 0:
                log.error("Item fetch failed after re-auth: %s", result.stderr.strip())
                raise HTTPException(status_code=404, detail=f"Item not found: {item}")
        else:
            log.error("Session valid but item fetch failed: %s", result.stderr.strip())
            raise HTTPException(status_code=404, detail=f"Item not found: {item}")

    log.info("Item fetched successfully: %s", uri)
    return json.loads(result.stdout)


# ── Field extraction ──────────────────────────────────────────────────────────

def _get_extra_field(extra_fields: list, field: str) -> str | None:
    for ef in extra_fields:
        if ef.get("name") == field:
            fc = ef.get("content", {})
            value = fc.get("Hidden") or fc.get("Text") or fc.get("Totp")
            if value is not None:
                return str(value)
    return None


def _get_login_field(login_data: dict, field: str) -> str | None:
    mapping = {
        "username": login_data.get("username"),
        "password": login_data.get("password"),
        "email":    login_data.get("email"),
        "totp":     login_data.get("totp"),
        "url":      (login_data.get("urls") or [None])[0],
    }
    return str(mapping[field]) if field in mapping and mapping[field] is not None else None


def _get_card_field(card: dict, field: str) -> str | None:
    mapping = {
        "cardholder_name":  card.get("cardholder_name"),
        "number":           card.get("number"),
        "expiration_date":  card.get("expiration_date"),
        "verif_number":     card.get("verif_number"),
        "pin":              card.get("pin"),
    }
    return str(mapping[field]) if field in mapping and mapping[field] is not None else None


def _get_wifi_field(wifi: dict, field: str) -> str | None:
    mapping = {
        "ssid":     wifi.get("ssid"),
        "password": wifi.get("password"),
    }
    return str(mapping[field]) if field in mapping and mapping[field] is not None else None


def extract_field(data: dict, field: str) -> str:
    content  = data.get("item", {}).get("content", {})
    title    = content.get("title", "")
    note     = content.get("note", "")
    type_map = content.get("content", {})
    extra    = content.get("extra_fields", [])
    item_type = list(type_map.keys())[0] if type_map else "Unknown"

    log.info("Extracting field '%s' from %s item '%s'", field, item_type, title)

    if field == "title":
        return title
    if field == "note":
        return note

    value = _get_extra_field(extra, field)
    if value is not None:
        return value

    if "Login" in type_map:
        value = _get_login_field(type_map["Login"], field)
        if value is not None:
            return value

    if "CreditCard" in type_map:
        value = _get_card_field(type_map["CreditCard"], field)
        if value is not None:
            return value

    if "Wifi" in type_map:
        value = _get_wifi_field(type_map["Wifi"], field)
        if value is not None:
            return value

    available_extra = [ef.get("name") for ef in extra]
    log.error("Field '%s' not found in %s item '%s'. Available: %s", field, item_type, title, available_extra)
    raise HTTPException(
        status_code=404,
        detail=f"Field '{field}' not found in {item_type} item '{title}'. "
               f"Custom fields available: {available_extra}"
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/secret/{item}/{field}")
def get_secret(
    item: str,
    field: str,
    creds: HTTPAuthorizationCredentials = Security(bearer),
):
    verify_token(creds)
    data  = get_item_json(item)
    value = extract_field(data, field)
    return {"value": value}


@app.get("/fields/{item}")
def list_fields(
    item: str,
    creds: HTTPAuthorizationCredentials = Security(bearer),
):
    verify_token(creds)
    log.info("Listing fields for pass://%s/%s", VAULT, item)
    data     = get_item_json(item)
    content  = data.get("item", {}).get("content", {})
    type_map = content.get("content", {})
    extra    = content.get("extra_fields", [])
    item_type = list(type_map.keys())[0] if type_map else "Unknown"

    fields = ["title", "note"]
    if "Login" in type_map:
        fields += ["username", "password", "email", "url", "totp"]
    if "CreditCard" in type_map:
        fields += ["cardholder_name", "number", "expiration_date", "verif_number", "pin"]
    if "Wifi" in type_map:
        fields += ["ssid", "password"]
    fields += [ef.get("name") for ef in extra if ef.get("name")]

    return {"item": item, "type": item_type, "fields": fields}