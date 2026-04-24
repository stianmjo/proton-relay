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

# ── Startup: authenticate pass-cli ───────────────────────────────────────────

def login():
    log.info("Authenticating pass-cli with PAT…")
    env = {
        **os.environ,
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN": PAT,
        "PROTON_PASS_KEY_PROVIDER": "env",
        "PROTON_PASS_ENCRYPTION_KEY": ENC_KEY,
    }
    result = subprocess.run(
        ["pass-cli", "login"],
        env=env,
        capture_output=True,
        text=True,
    )
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


# ── Secret fetch ──────────────────────────────────────────────────────────────

def fetch_secret(item: str, field: str) -> str:
    """
    Fetch full item JSON (no field in URI) and extract the field ourselves.
    pass-cli returns a raw scalar when the field is included in the URI,
    which breaks JSON parsing.
    """
    uri = f"pass://{VAULT}/{item}"
    log.info("Fetching %s field=%s", uri, field)

    env = {
        **os.environ,
        "PROTON_PASS_KEY_PROVIDER": "env",
        "PROTON_PASS_ENCRYPTION_KEY": ENC_KEY,
    }
    result = subprocess.run(
        ["pass-cli", "item", "view", uri, "--output", "json"],
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        log.error("pass-cli error for %s:\n%s", uri, result.stderr)
        raise HTTPException(status_code=404, detail=f"Secret not found: {uri}")

    log.debug("pass-cli raw output: %s", result.stdout[:200])

    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected output type {type(data)}: {data}")
        value = _extract_field(data, field)
    except Exception as exc:
        log.error("Failed to parse pass-cli output: %s", exc)
        log.error("Raw output: %s", result.stdout[:500])
        raise HTTPException(status_code=500, detail="Failed to parse secret") from exc

    return value


def _extract_field(data: dict, field: str) -> str:
    """
    Standard fields (password, username, email, url, note) are top-level.
    Custom fields live in data["extraFields"][n]["fieldName"] / ["data"]["content"].
    """
    # Standard top-level fields
    if field in data:
        return str(data[field])

    # Custom fields
    for ef in data.get("extraFields", []):
        if ef.get("fieldName") == field:
            return str(ef["data"]["content"])

    raise ValueError(f"Field '{field}' not found in item. Available keys: {list(data.keys())}")


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
    value = fetch_secret(item, field)
    return {"value": value}