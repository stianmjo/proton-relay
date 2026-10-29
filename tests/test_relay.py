import json
import logging
import os
import re
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import httpx
import pytest

from conftest import AUTH, HERE, REAL_BIN, ROOT, Server

EXPECTED = json.loads((HERE / "expected_get_field.json").read_text())       # pass-cli's own get_field()
EXPECTED_NAMES = json.loads((HERE / "expected_field_names.json").read_text())  # pass-cli's own fields()
ALLOWED_ITEMS = {"smtp-relay", "shadowed", "cloudflare-api", "just-a-note"}
BLOCKED_ITEMS = {"visa", "home-wifi"}


def secret_values():
    """Every sensitive value present in the fixtures — must never reach a log line."""
    vals = set()
    for f in (HERE / "fixtures").glob("*.json"):
        if f.name == "folders.json":
            continue
        c = json.loads(f.read_text())["item"]["content"]
        body = next(iter(c["content"].values())) or {}
        for k in ("password", "number", "verification_number", "pin", "totp_uri"):
            if isinstance(body, dict) and body.get(k):
                vals.add(body[k])
        fields = list(c["extra_fields"])
        for s in (body.get("sections") or []) if isinstance(body, dict) else []:
            fields += s["section_fields"]
        vals |= {v for fl in fields for k, v in fl["content"].items() if k in ("Hidden", "Totp") and v}
    # Short values (CVV "123", PIN "0000") collide with log timestamps/line numbers; only scan distinctive ones.
    return {v for v in vals if len(v) >= 6}


def url(key, endpoint="secret"):
    return f"/{endpoint}/{quote(key, safe='/:')}"


def calls(env, cmd):
    """argv of every pass-cli call of one command, e.g. calls(env, 'item view')."""
    return [c["argv"] for c in env.calls() if " ".join(c["argv"][:len(cmd.split())]) == cmd]


def after_startup(env):
    return [" ".join(a for a in c["argv"][:2] if not a.startswith("-")) for c in env.calls()[3:]]


def relay_records(caplog, level=logging.DEBUG):
    return [r for r in caplog.records if r.name == "proton-relay" and r.levelno >= level]


# ── 1. Startup contract ───────────────────────────────────────────────────────

def test_startup_sequence_and_child_env(relay):
    calls_ = relay.env.calls()
    assert [c["argv"] for c in calls_] == [["logout", "--force"], ["login"], ["info"]]
    assert all(c["key_provider"] == "fs" for c in calls_)          # hard-won fix preserved
    assert all(c["backtrace"] == "0" for c in calls_)              # backtraces suppressed
    assert all(c["has_pat"] for c in calls_)
    assert relay.c.get("/ready").json() == {"ready": True}
    assert relay.c.get("/health").json() == {"status": "ok"}


def test_bearer_auth(relay):
    assert relay.c.get(url("smtp-relay/password")).status_code in (401, 403)
    assert relay.c.get(url("smtp-relay/password"), headers={"Authorization": "Bearer nope"}).status_code == 401
    r = relay.c.get(url("smtp-relay/password"), headers=AUTH)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"


def test_openapi_disabled(relay):
    assert relay.c.get("/docs").status_code == 404
    assert relay.c.get("/openapi.json").status_code == 404


@pytest.mark.parametrize("missing", ["BRIDGE_TOKEN", "PROTON_PASS_VAULT", "PROTON_PASS_PERSONAL_ACCESS_TOKEN"])
def test_missing_env_exits_cleanly(mock_env, missing):
    env = {k: v for k, v in os.environ.items() if k != missing}
    p = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert p.returncode == 1 and missing in p.stdout and "Traceback" not in p.stderr


# ── 2. Field parity with pass-cli's own resolver (root items) ────────────────

CASES = [(t, q, v) for t, per in EXPECTED.items() for q, v in per.items() if q]


@pytest.mark.parametrize("title,query,expected", CASES, ids=[f"{t}:{q}" for t, q, _ in CASES])
def test_get_field_parity_with_pass_cli(relay, title, query, expected):
    r = relay.c.get(url(f"{title}/{query}"), headers=AUTH)
    if title in BLOCKED_ITEMS:
        assert r.status_code == 403
    elif expected is None:
        assert r.status_code == 404, r.text
    else:
        assert r.status_code == 200, r.text
        assert r.json() == {"value": expected}


@pytest.mark.parametrize("title", sorted(ALLOWED_ITEMS))
def test_field_names_parity_with_pass_cli(relay, title):
    want = EXPECTED_NAMES[title] + (["url"] if title == "smtp-relay" else [])
    got = relay.c.get(url(title, "fields"), headers=AUTH).json()
    assert got["fields"] == list(dict.fromkeys(want))
    assert got["item"] == title and got["id"].startswith("item_")


def test_url_alias_kept_for_existing_consumers(relay):
    assert relay.c.get(url("smtp-relay/url"), headers=AUTH).json() == {"value": "https://smtp.protonmail.ch"}


# ── 3. Keys: folder paths and IDs ─────────────────────────────────────────────

@pytest.mark.parametrize("key,value", [
    ("authentik/postgres/password", "auth-pg-PASSWORD"),
    ("media/postgres/password", "media-pg-PASSWORD"),
    ("authentik/db/postgres/password", "auth-db-pg-PASSWORD"),     # nested folder
    ("id:item_11/password", "media-pg-PASSWORD"),                  # ID: folder doesn't matter
    ("id:item_13/password", "twin-a-PASSWORD"),                    # ID: escape hatch for duplicate titles
    ("smtp-relay/password", "login-password-VALUE"),               # trashed duplicate is ignored
])
def test_key_resolves_exact_item(relay, key, value):
    r = relay.c.get(url(key), headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.json() == {"value": value}


@pytest.mark.parametrize("key,status,detail", [
    ("postgres/password", 404, "Item not found: postgres"),               # root holds no "postgres"
    ("Authentik/postgres/password", 404, "Folder not found: Authentik"),  # folder names are exact
    ("authentik/nope/password", 404, "Item not found: authentik/nope"),
    ("authentik/missing/postgres/password", 404, "Folder not found: authentik/missing"),
    ("db/postgres/password", 404, "Folder not found: db"),                # db is not at the root
    ("id:item_15/password", 404, "Item not found: id:item_15"),           # trashed
    ("id:does-not-exist/password", 404, "Item not found: id:does-not-exist"),
    ("twin/password", 409, "use one of id:item_13, id:item_14"),
    ("dup/postgres/password", 409, "Ambiguous folder: 2 folders at dup"),
    ("smtp-relay", 400, "key must be"),                                   # no field
    ("smtp-relay/", 400, "key must be"),
    ("a//smtp-relay/password", 400, "key must be"),
    ("id:/password", 400, "key must be"),
    ("id:item_1/extra/password", 400, "key must be"),
])
def test_key_errors(relay, key, status, detail):
    r = relay.c.get(url(key), headers=AUTH)
    assert r.status_code == status, r.text
    assert detail in r.json()["detail"]
    assert ["login"] not in [c["argv"] for c in relay.env.calls()[3:]]   # never mistaken for a broken session


def test_fields_endpoint_takes_same_keys(relay):
    assert relay.c.get(url("authentik/db/postgres", "fields"), headers=AUTH).json() == {
        "item": "authentik/db/postgres", "id": "item_12", "type": "Login",
        "fields": ["title", "username", "password"]}
    assert relay.c.get(url("id:item_12", "fields"), headers=AUTH).json()["item"] == "id:item_12"
    assert relay.c.get(url("twin", "fields"), headers=AUTH).status_code == 409
    assert relay.c.get("/fields/", headers=AUTH).status_code == 400


def test_lookup_argv(relay):
    relay.c.get(url("smtp-relay/password"), headers=AUTH)
    assert calls(relay.env, "folder list") == []                     # root keys skip the folder lookup
    relay.c.get(url("authentik/db/postgres/password"), headers=AUTH)
    assert calls(relay.env, "item list")[-1] == [
        "item", "list", "--filter-state=active", "--vault-name=Homelab", "--output=json"]
    assert calls(relay.env, "folder list") == [["folder", "list", "--vault-name=Homelab", "--output=json"]]
    assert calls(relay.env, "item view")[-1] == [
        "item", "view", "--item-id=item_12", "--vault-name=Homelab", "--output=json"]


@pytest.mark.parametrize("title", ["-leading-dash", "spaces and ?query=1#frag", "ümlaut ✓"])
def test_titles_never_reach_argv(relay, title):
    fx = json.loads((HERE / "fixtures" / "smtp-relay.json").read_text())
    fx["item"].update(id="item_odd")
    fx["item"]["content"]["title"] = title
    (relay.env.fixtures / "odd.json").write_text(json.dumps(fx))
    assert relay.c.get(url(f"{title}/password"), headers=AUTH).json() == {"value": "login-password-VALUE"}
    assert not [a for c in relay.env.calls() for a in c["argv"] if title in a]


# ── 4. Allowlist: card/wifi never served, never even read ────────────────────

@pytest.mark.parametrize("title,field", [("visa", "number"), ("visa", "cvv"), ("home-wifi", "password")])
def test_blocked_types(relay, caplog, title, field):
    r = relay.c.get(url(f"{title}/{field}"), headers=AUTH)
    assert r.status_code == 403
    assert relay.c.get(url(title, "fields"), headers=AUTH).status_code == 403
    assert calls(relay.env, "item view") == []                       # refused from metadata alone
    for v in ("4111111111111111", "123", "0000", "wifi-pw"):
        assert v not in r.text
    for v in ("4111111111111111", "wifi-pw"):   # short values collide with log line numbers/timestamps
        assert v not in caplog.text


def test_blocked_types_not_cached(relay_factory, monkeypatch):
    monkeypatch.setenv("CACHE_TTL_SECONDS", "300")
    r = relay_factory()
    r.c.get(url("visa/number"), headers=AUTH)
    assert not r.mod._cache


def test_sshkey_is_opt_in(relay_factory, monkeypatch):
    monkeypatch.setenv("ALLOWED_ITEM_TYPES", "Login,Custom,Note,SshKey")
    r = relay_factory()
    assert r.mod.ALLOWED_TYPES == {"Login", "Custom", "Note", "SshKey"}


@pytest.mark.parametrize("types", ["Login,CreditCard", "Wifi", "Identity"])
def test_unsupported_types_refused_at_startup(mock_env, types):
    env = dict(os.environ, ALLOWED_ITEM_TYPES=types)
    p = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert p.returncode == 1 and "unsupported types" in p.stdout


# ── 5. Session handling ──────────────────────────────────────────────────────

def test_reauth_on_expired_session(relay):
    relay.env.flag("expire_next")
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).json() == {"value": "login-password-VALUE"}
    assert after_startup(relay.env) == ["item list", "logout", "login", "info", "item list", "item view"]


def test_reauth_failure_then_recovery_on_next_request(relay):
    """Regression (v2.0.x): a failed re-login flipped /ready to 503, Kubernetes pulled the only pod out of
    the Service, no request could reach it to trigger the next login, and it stayed broken until restarted.
    /ready now stays 200 after startup; the relay answers 503 itself and heals on the next request."""
    relay.env.flag("expire_next")
    relay.env.flag("login_fail")
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 503
    assert relay.c.get("/ready").status_code == 200
    (relay.env.dir / "login_fail").unlink()
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 200


def test_failed_login_backs_off(relay_factory, monkeypatch):
    """Repeated logins trip Proton's rate limit (code 2028): after a failure, no new login for a while."""
    monkeypatch.setenv("LOGIN_BACKOFF_SECONDS", "300")
    r = relay_factory()
    r.env.flag("expire_next")
    r.env.flag("login_fail")
    assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 503
    (r.env.dir / "login_fail").unlink()
    logins = len(calls(r.env, "login"))
    for _ in range(3):
        assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 503
    assert len(calls(r.env, "login")) == logins                    # no login while backing off
    assert r.c.get("/ready").status_code == 200                   # stays in the Service, so it can heal
    r.mod._state["login_after"] = 0.0                              # backoff elapsed
    assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 200


def test_regression_unpersisted_refresh_triggers_reauth(relay):
    """2026-09-23..30 outage: pass-cli refreshed the token, failed to persist it ("background task failed"),
    and every later call failed with "Error finding vault [..]: Error listing vaults". v2.0.0 read that as a
    wrong vault (500) and never re-logged in. `info` keeps succeeding in this state, so it can't be the gate."""
    relay.env.flag("stale")
    r = relay.c.get(url("smtp-relay/password"), headers=AUTH)
    assert r.status_code == 200, r.text
    assert after_startup(relay.env) == ["item list", "logout", "login", "info", "item list", "item view"]


def test_regression_stale_session_with_failed_relogin_is_503(relay):
    relay.env.flag("stale")
    relay.env.flag("login_fail")
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 503


def test_still_failing_after_relogin_is_502_and_retried_once(relay, caplog):
    relay.env.flag("broken")
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 502
    assert after_startup(relay.env) == ["item list", "logout", "login", "info", "item list"]
    assert [r.getMessage() for r in relay_records(caplog, logging.ERROR)] == [
        "pass-cli still failing after re-login: Error: Error listing items | Caused by: | 0: Error fetching items "
        "| 1: Error sending request | 2: upstream connect error"]


def test_wrong_vault_is_500_without_reauth(relay_factory, monkeypatch):
    monkeypatch.setenv("PROTON_PASS_VAULT", "NoSuchVault")
    r = relay_factory()
    assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 500
    assert ["login"] not in [c["argv"] for c in r.env.calls()[3:]]


def test_garbage_output_is_502_without_reauth(relay_factory, monkeypatch):
    monkeypatch.setenv("MOCK_GARBAGE_TITLE", "smtp-relay")
    r = relay_factory()
    assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 502
    assert ["login"] not in [c["argv"] for c in r.env.calls()[3:]]


def test_unexpected_list_shape_is_502(relay):
    relay.env.flag("bad_list")
    assert relay.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 502


def test_timeout_is_504_and_lock_released(relay_factory, monkeypatch):
    monkeypatch.setenv("PASS_CLI_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("MOCK_HANG_TITLE", "cloudflare-api")
    r = relay_factory()
    t0 = time.time()
    assert r.c.get(url("cloudflare-api/token"), headers=AUTH).status_code == 504
    assert time.time() - t0 < 5
    assert r.c.get(url("smtp-relay/password"), headers=AUTH).status_code == 200


# ── 6. Agent reason, cache ───────────────────────────────────────────────────

def test_agent_reason_on_data_calls_only(relay):
    relay.c.get(url("authentik/postgres/password"), headers=AUTH)
    relay.c.get(url("x" * 400 + "/password"), headers=AUTH)
    data = [c for c in relay.env.calls() if c["argv"][0] in ("item", "folder")]
    assert all("authentik/postgres" in c["reason"] for c in data[:3])
    assert len(data[-1]["reason"]) == 300                                       # truncated
    assert all(c["reason"] is None for c in relay.env.calls() if c["argv"][0] not in ("item", "folder"))


def test_operator_agent_reason_wins(relay_factory, monkeypatch):
    monkeypatch.setenv("PROTON_PASS_AGENT_REASON", "ops-defined reason")
    r = relay_factory()
    r.c.get(url("smtp-relay/password"), headers=AUTH)
    assert r.env.calls()[-1]["reason"] == "ops-defined reason"


def test_cache_per_item(relay_factory, monkeypatch):
    monkeypatch.setenv("CACHE_TTL_SECONDS", "60")
    r = relay_factory()
    for f in ("password", "username", "api_key", "region"):
        assert r.c.get(url(f"smtp-relay/{f}"), headers=AUTH).status_code == 200
    assert r.c.get(url("id:item_1", "fields"), headers=AUTH).status_code == 200   # different key, own entry
    assert len(calls(r.env, "item list")) == 2 and len(calls(r.env, "item view")) == 2


def test_cache_disabled(relay):
    for f in ("password", "username"):
        relay.c.get(url(f"smtp-relay/{f}"), headers=AUTH)
    assert len(calls(relay.env, "item view")) == 2


# ── 7. Logs: no secrets, no noise ────────────────────────────────────────────

def test_no_secret_values_in_logs(relay, caplog):
    caplog.set_level("DEBUG")
    relay.env.flag("expire_next")
    keys = [f"{t}/{q}" for t, q, _ in CASES] + ["authentik/postgres/password", "id:item_13/password", "twin/password"]
    for k in keys:
        relay.c.get(url(k), headers=AUTH)
    assert "Served smtp-relay/password" in caplog.text          # caplog really captures relay logs
    assert {"cf-api-token", "login-password-VALUE", "4111111111111111", "twin-b-PASSWORD"} <= secret_values()
    leaked = [v for v in secret_values() if v in caplog.text]
    assert not leaked, leaked


def test_routine_reauth_is_one_info_line(relay, caplog):
    caplog.set_level("DEBUG")
    relay.env.flag("expire_next")
    relay.c.get(url("smtp-relay/password"), headers=AUTH)
    relay.env.flag("stale")
    relay.c.get(url("smtp-relay/username"), headers=AUTH)
    assert not relay_records(caplog, logging.WARNING)
    info = [r.getMessage() for r in relay_records(caplog, logging.INFO)]
    assert info == ["Re-authenticated (This operation requires an authenticated client)",
                    "Served smtp-relay/password",
                    "Re-authenticated (Error finding vault [Homelab]: Error listing vaults)",
                    "Served smtp-relay/username"]
    assert any("pass-cli item list failed (exit 1)" in r.getMessage() for r in relay_records(caplog))  # DEBUG


@pytest.mark.parametrize("key,message", [
    ("twin/password", "Refused twin/password: Ambiguous: 2 items match twin; use one of id:item_13, id:item_14"),
    ("smtp-relay/nope", "Refused smtp-relay/nope: field not found"),
    ("visa/number", "Refused visa/number: Item type CreditCard is not served by this relay"),
])
def test_refused_request_is_one_warning(relay, caplog, key, message):
    relay.c.get(url(key), headers=AUTH)
    assert [r.getMessage() for r in relay_records(caplog, logging.WARNING)] == [message]


def test_failed_relogin_is_one_error(relay, caplog):
    relay.env.flag("expire_next")
    relay.env.flag("login_fail")
    relay.c.get(url("smtp-relay/password"), headers=AUTH)
    assert [r.getMessage() for r in relay_records(caplog, logging.WARNING)] == [
        "Session lost (This operation requires an authenticated client); re-login failed: "
        "Error: Error in personal access token login flow | Caused by: | "
        "0: Error creating personal access token session | 1: Too many recent logins"]


def test_stderr_condensed(relay):
    raw = ("\x1b[2m2026-09-23T10:27:07Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2mpass-cli/src/main.rs\x1b[0m: no session\n"
           "Error: Error getting base dir\n\nCaused by:\n    Session directory is accessible by group or others\n\n"
           "Stack backtrace:\n   0: anyhow::error::msg\n")
    out = relay.mod.condense(raw)
    assert out == "Error: Error getting base dir | Caused by: | Session directory is accessible by group or others"
    assert relay.mod.CliError(out).short == "Session directory is accessible by group or others"
    assert relay.mod.CliError("Error: x | Caused by: | 4: non-existent session").short == "non-existent session"


def test_access_log_drops_successful_probes_only(mock_env, tmp_path):
    srv = Server("app", dict(os.environ), tmp_path / "access.log", log_level="info")
    try:
        assert srv.wait_ready(), srv.stop()
        with httpx.Client(base_url=srv.url, timeout=30) as c:
            for _ in range(5):
                assert c.get("/health").status_code == 200
                assert c.get("/ready").status_code == 200
            assert c.get(url("smtp-relay/password"), headers=AUTH).status_code == 200
            assert c.get(url("smtp-relay/password")).status_code in (401, 403)
            mock_env.flag("stale")                     # broken session + failing re-login -> 503
            mock_env.flag("login_fail")
            assert c.get(url("cloudflare-api/token"), headers=AUTH).status_code == 503
    finally:
        log = srv.stop()
    access = [line for line in log.splitlines() if '" ' in line and " HTTP/1.1" in line]
    assert not [line for line in access if '"GET /health ' in line or '"GET /ready ' in line], access
    assert len([line for line in access if "GET /secret/" in line]) == 3, access         # real traffic stays
    assert [line for line in access if "GET /secret/" in line and " 503" in line], access
    # A failing probe (e.g. kubelet timing out the app) would still be logged:
    import conftest
    probe = conftest.load("app")._ProbeAccessFilter()
    rec = lambda status: logging.LogRecord("uvicorn.access", 20, "", 0, '%s - "%s %s HTTP/%s" %d',
                                           ("1.2.3.4:5", "GET", "/ready", "1.1", status), None)
    assert not probe.filter(rec(200)) and probe.filter(rec(503))


# ── 8. Concurrency under a real uvicorn server ───────────────────────────────

def _burst(module, mock_env, tmp_path, n=16):
    env = dict(os.environ, MOCK_LATENCY="0.1", CACHE_TTL_SECONDS="0")
    srv = Server(module, env, tmp_path / f"{module}.log")
    try:
        assert srv.wait_ready(), srv.stop()
        before = mock_env.overlaps()
        keys = ["smtp-relay/password", "authentik/postgres/password", "cloudflare-api/token", "id:item_4/note"]
        with httpx.Client(base_url=srv.url, headers=AUTH, timeout=60) as c, ThreadPoolExecutor(n) as pool:
            codes = list(pool.map(lambda i: c.get(url(keys[i % 4])).status_code, range(n)))
        return codes, mock_env.overlaps() - before, srv
    finally:
        srv.log_text = srv.stop()


def test_concurrent_burst(mock_env, tmp_path):
    codes, overlaps, srv = _burst("app", mock_env, tmp_path)
    assert overlaps == 0
    assert codes == [200] * len(codes)
    assert not [v for v in secret_values() if v in srv.log_text]


def test_mutation_without_lock_the_race_returns(mock_env, tmp_path):
    src = (ROOT / "app.py").read_text()
    assert "_cli_lock = threading.Lock()" in src
    nolock = src.replace("_cli_lock = threading.Lock()", """class _NoLock:
    def acquire(self, timeout=None): return True
    def release(self): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass
_cli_lock = _NoLock()""")
    (ROOT / "app_nolock.py").write_text(nolock)
    try:
        codes, overlaps, _ = _burst("app_nolock", mock_env, tmp_path)
    finally:
        (ROOT / "app_nolock.py").unlink()
    assert overlaps > 0, "the burst test would not detect a missing lock"


# ── 9. Real pass-cli binary ──────────────────────────────────────────────────

def _real_version():
    try:
        out = subprocess.run([str(REAL_BIN), "--version"], capture_output=True, text=True, timeout=10).stdout
    except OSError:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(map(int, m.groups())) if m else None


NEEDS_25 = pytest.mark.skipif((_real_version() or (0,)) < (2, 5, 0),
                              reason="real pass-cli >= 2.5.0 not available (folders + item list JSON)")


@pytest.fixture
def real_env(tmp_path, monkeypatch):
    bindir = tmp_path / "realbin"
    bindir.mkdir()
    (bindir / "pass-cli").symlink_to(REAL_BIN)
    sess = tmp_path / "realsession"
    (sess / ".session").mkdir(parents=True)
    os.chmod(sess / ".session", 0o2770)                      # what fsGroup does on a PVC
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "pst_" + "a" * 64 + "::" + "A" * 43,  # well-formed (valid base64url), fake
        "PROTON_PASS_VAULT": "Homelab",
        "BRIDGE_TOKEN": "x",
        "PROTON_PASS_SESSION_DIR": str(sess),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return sess


def _cli_error(fn):
    import conftest
    mod = conftest.load("app")
    with pytest.raises(mod.CliError) as e:
        fn(mod)
    return mod, e.value.detail


@NEEDS_25
def test_real_binary_rejects_loose_session_dir_until_relay_fixes_it(real_env):
    mod, err = _cli_error(lambda m: m.pass_cli(["info"]))
    assert "accessible by group or others" in err                 # pass-cli refuses 2770
    mod.prepare_session_dir()
    assert stat.S_IMODE((real_env / ".session").stat().st_mode) == 0o2700   # setgid kept, g/o cleared
    _, err = _cli_error(lambda m: m.pass_cli(["info"]))
    assert mod.NO_SESSION in err                                  # now past the base-dir check


@NEEDS_25
def test_real_binary_symlinked_session_dir_fails_fast(real_env, tmp_path, monkeypatch):
    import conftest
    link = tmp_path / "linked"
    link.symlink_to(real_env)
    monkeypatch.setenv("PROTON_PASS_SESSION_DIR", str(link))
    mod = conftest.load("app")
    with pytest.raises(RuntimeError, match="symlink"):
        mod.prepare_session_dir()


@NEEDS_25
@pytest.mark.parametrize("args", [
    ["item", "list", "--filter-state=active"],
    ["folder", "list"],
    ["item", "view", "--item-id=" + "A" * 86 + "=="],
])
def test_real_binary_accepts_relay_argv(real_env, args):
    import conftest
    conftest.load("app").prepare_session_dir()
    mod, err = _cli_error(lambda m: m.pass_cli_json(args, "test"))
    assert mod.NO_SESSION in err             # clap accepted the argv; failed only on auth


@NEEDS_25
def test_real_binary_startup_exits_cleanly_without_proton(real_env, tmp_path):
    srv = Server("app", dict(os.environ), tmp_path / "real.log")
    srv.proc.wait(60)
    log = srv.stop()
    print("\n" + log)
    assert srv.proc.returncode != 0
    assert "tightening to 2700" in log
    assert "Login to Proton Pass failed: Error: Error in personal access token login flow" in log
    assert "Error creating personal access token session" in log   # got past PAT parsing into networking
    assert "\x1b[" not in log and "Stack backtrace" not in log
    assert "a" * 64 not in log                     # PAT never logged