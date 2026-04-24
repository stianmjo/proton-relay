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

# Set pass-cli env vars on the process so all subprocesses inherit them
os.environ["PROTON_PASS_KEY_PROVIDER"]   = "env"
os.environ["PROTON_PASS_ENCRYPTION_KEY"] = ENC_KEY

# ── Startup ───────────────────────────────────────────────────────────────────

def login():
    log.info("Authenticating pass-cli with PAT…")
    result = subprocess.run(["pass-cli", "login"], capture_output=True, text=True)
    if result.returncode != 0:
        log.error("pass-cli login failed:\n%s", result.stderr)
        sys.exit(1)
    log.info("pass-cli login successful")


@asynccontextmanager
async def lifespan(app: FastAPI):
    login()
    yield


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="proton-relay", lifespan=lifespan)
bearer = HTTPBearer()


def verify_token(creds: HTTPAuthorizationCredentials = Security(bearer)):
    if creds.credentials != BRIDGE_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


# ── pass-cli wrapper ──────────────────────────────────────────────────────────

def get_item_json(item: str) -> dict:
    uri = f"pass://{VAULT}/{item}"
    result = subprocess.run(
        ["pass-cli", "item", "view", uri, "--output", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("pass-cli error for %s:\n%s", uri, result.stderr)
        raise HTTPException(status_code=404, detail=f"Item not found: {item}")
    return json.loads(result.stdout)


# ── Field extraction ──────────────────────────────────────────────────────────

def _get_extra_field(extra_fields: list, field: str) -> str | None:
    """
    Custom/extra fields — present on all item types.
    JSON: extra_fields[n].name + extra_fields[n].content.{Hidden|Text|Totp}
    """
    for ef in extra_fields:
        if ef.get("name") == field:
            fc = ef.get("content", {})
            # Hidden = secret value, Text = plaintext, Totp = TOTP URI
            value = fc.get("Hidden") or fc.get("Text") or fc.get("Totp")
            if value is not None:
                return str(value)
    return None


def _get_login_field(login: dict, field: str) -> str | None:
    """
    Login item standard fields.
    JSON: item.content.content.Login.{username|password|email|urls|totp|note}
    """
    mapping = {
        "username":  login.get("username"),
        "password":  login.get("password"),
        "email":     login.get("email"),
        "totp":      login.get("totp"),
        # urls is a list — return first entry for simplicity
        "url":       (login.get("urls") or [None])[0],
    }
    return str(mapping[field]) if field in mapping and mapping[field] is not None else None


def _get_card_field(card: dict, field: str) -> str | None:
    """
    Credit card item fields.
    JSON: item.content.content.CreditCard.{cardholder_name|number|expiration_date|verif_number|pin}
    """
    mapping = {
        "cardholder_name":   card.get("cardholder_name"),
        "number":            card.get("number"),
        "expiration_date":   card.get("expiration_date"),
        "verif_number":      card.get("verif_number"),   # CVV
        "pin":               card.get("pin"),
    }
    return str(mapping[field]) if field in mapping and mapping[field] is not None else None


def _get_wifi_field(wifi: dict, field: str) -> str | None:
    """
    Wifi item fields.
    JSON: item.content.content.Wifi.{ssid|password}
    """
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

    # ── Common fields ─────────────────────────────────────────────────────────
    if field == "title":
        return title
    if field == "note":
        return note

    # ── Extra / custom fields (all item types) ─────────────────────────────
    value = _get_extra_field(extra, field)
    if value is not None:
        return value

    # ── Type-specific standard fields ─────────────────────────────────────
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

    # Note items: the note text is already covered by "note" above.
    # SSH key items expose the key via extra_fields in practice.

    # ── Nothing found ─────────────────────────────────────────────────────
    available_extra = [ef.get("name") for ef in extra]
    item_type = list(type_map.keys())[0] if type_map else "Unknown"
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
    """Fetch a single field from a Proton Pass item."""
    verify_token(creds)
    log.info("Fetching pass://%s/%s field=%s", VAULT, item, field)
    data  = get_item_json(item)
    value = extract_field(data, field)
    return {"value": value}


@app.get("/fields/{item}")
def list_fields(
    item: str,
    creds: HTTPAuthorizationCredentials = Security(bearer),
):
    """
    Discovery endpoint — lists all available fields for an item.
    Useful for debugging ExternalSecret key names.
    """
    verify_token(creds)
    log.info("Listing fields for pass://%s/%s", VAULT, item)
    data    = get_item_json(item)
    content = data.get("item", {}).get("content", {})
    type_map = content.get("content", {})
    extra   = content.get("extra_fields", [])
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