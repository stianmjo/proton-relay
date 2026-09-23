import json
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

from conftest import AUTH, HERE, REAL_BIN, ROOT, TOKEN, Server

EXPECTED = json.loads((HERE / "expected_get_field.json").read_text())       # pass-cli's own get_field()
EXPECTED_NAMES = json.loads((HERE / "expected_field_names.json").read_text())  # pass-cli's own fields()
OLD = pytest.mark.skipif(not (ROOT / "original_main.py").exists(), reason="copy the pre-upgrade main.py to original_main.py to run old-vs-new tests")
ALLOWED_ITEMS = {"smtp-relay", "shadowed", "cloudflare-api", "just-a-note"}
BLOCKED_ITEMS = {"visa", "home-wifi"}


def secret_values():
    """Every sensitive value present in the fixtures — must never reach a log line."""
    vals = set()
    for f in (HERE / "fixtures").glob("*.json"):
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


def url(item, field=None):
    return f"/secret/{quote(item, safe='')}/{quote(field, safe='')}" if field else f"/fields/{quote(item, safe='')}"


# ── 1. Startup contract ───────────────────────────────────────────────────────

def test_startup_sequence_and_child_env(relay):
    calls = relay.env.calls()
    assert [c["argv"] for c in calls] == [["logout", "--force"], ["login"], ["info"]]
    assert all(c["key_provider"] == "fs" for c in calls)          # hard-won fix preserved
    assert all(c["backtrace"] == "0" for c in calls)              # backtraces suppressed
    assert all(c["has_pat"] for c in calls)
    assert relay.c.get("/ready").json() == {"ready": True}
    assert relay.c.get("/health").json() == {"status": "ok"}


def test_bearer_auth(relay):
    assert relay.c.get(url("smtp-relay", "password")).status_code in (401, 403)
    assert relay.c.get(url("smtp-relay", "password"), headers={"Authorization": "Bearer nope"}).status_code == 401
    r = relay.c.get(url("smtp-relay", "password"), headers=AUTH)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"


def test_openapi_disabled(relay):
    assert relay.c.get("/docs").status_code == 404
    assert relay.c.get("/openapi.json").status_code == 404


# ── 2. Parity with pass-cli's own resolver ───────────────────────────────────

CASES = [(t, q, v) for t, per in EXPECTED.items() for q, v in per.items() if q]


@pytest.mark.parametrize("title,query,expected", CASES, ids=[f"{t}:{q}" for t, q, _ in CASES])
def test_get_field_parity_with_pass_cli(relay, title, query, expected):
    r = relay.c.get(url(title, query), headers=AUTH)
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
    got = relay.c.get(url(title), headers=AUTH).json()
    assert got["fields"] == list(dict.fromkeys(want))


def test_url_alias_kept_for_existing_consumers(relay):
    assert relay.c.get(url("smtp-relay", "url"), headers=AUTH).json() == {"value": "https://smtp.protonmail.ch"}


# ── 3. Allowlist: card/wifi never served ─────────────────────────────────────

@pytest.mark.parametrize("title,field", [("visa", "number"), ("visa", "cvv"), ("home-wifi", "password")])
def test_blocked_types(relay, caplog, title, field):
    r = relay.c.get(url(title, field), headers=AUTH)
    assert r.status_code == 403
    assert relay.c.get(url(title), headers=AUTH).status_code == 403
    for v in ("4111111111111111", "123", "0000", "wifi-pw"):
        assert v not in r.text
    for v in ("4111111111111111", "wifi-pw"):   # short values collide with log line numbers/timestamps
        assert v not in caplog.text


def test_blocked_types_not_cached(relay_factory, monkeypatch):
    monkeypatch.setenv("CACHE_TTL_SECONDS", "300")
    r = relay_factory()
    r.c.get(url("visa", "number"), headers=AUTH)
    assert "visa" not in r.mod._cache


def test_sshkey_is_opt_in(relay_factory, monkeypatch):
    monkeypatch.setenv("ALLOWED_ITEM_TYPES", "Login,Custom,Note,SshKey")
    r = relay_factory()
    assert r.mod.ALLOWED_TYPES == {"Login", "Custom", "Note", "SshKey"}


@pytest.mark.parametrize("types", ["Login,CreditCard", "Wifi", "Identity"])
def test_unsupported_types_refused_at_startup(mock_env, types):
    env = dict(os.environ, ALLOWED_ITEM_TYPES=types)
    p = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert p.returncode == 1 and "unsupported types" in p.stdout


@pytest.mark.parametrize("missing", ["BRIDGE_TOKEN", "PROTON_PASS_VAULT", "PROTON_PASS_PERSONAL_ACCESS_TOKEN"])
def test_missing_env_exits_cleanly(mock_env, missing):
    env = {k: v for k, v in os.environ.items() if k != missing}
    p = subprocess.run([sys.executable, "-c", "import app"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert p.returncode == 1 and missing in p.stdout and "Traceback" not in p.stderr


# ── 4. Old vs new on the same fixtures ───────────────────────────────────────

@pytest.mark.parametrize("title,field,value", [
    ("cloudflare-api", "token", "cf-api-token"),          # Custom-item section field
    ("cloudflare-api", "Zone.token", "cf-zone-token"),
    ("smtp-relay", "totp", "otpauth://totp/smtp?secret=JBSWY3DPEHPK3PXP"),
    ("smtp-relay", "API_KEY", "sk-live-1234"),             # case-insensitive
    ("smtp-relay", "rotated_at", "1790000000"),            # Timestamp field
])
@OLD
def test_old_relay_bug_fixed_in_new(relay_factory, title, field, value):
    old = relay_factory("original_main")
    assert old.c.get(url(title, field), headers=AUTH).status_code == 404   # bug in current relay
    new = relay_factory("app")
    assert new.c.get(url(title, field), headers=AUTH).json() == {"value": value}


@OLD
def test_old_relay_serves_card_numbers(relay_factory):
    old = relay_factory("original_main")
    assert old.c.get(url("visa", "number"), headers=AUTH).json() == {"value": "4111111111111111"}


# ── 5. Session handling ──────────────────────────────────────────────────────

def test_reauth_on_expired_session(relay):
    relay.env.flag("expire_next")
    r = relay.c.get(url("smtp-relay", "password"), headers=AUTH)
    assert r.json() == {"value": "login-password-VALUE"}
    tail = [c["argv"][:2] for c in relay.env.calls()[3:]]
    assert tail == [["item", "view"], ["logout", "--force"], ["login"], ["info"], ["item", "view"]]


def test_reauth_failure_then_recovery(relay):
    relay.env.flag("expire_next")
    relay.env.flag("login_fail")
    assert relay.c.get(url("smtp-relay", "password"), headers=AUTH).status_code == 503
    assert relay.c.get("/ready").status_code == 503
    (relay.env.dir / "login_fail").unlink()
    assert relay.c.get(url("smtp-relay", "password"), headers=AUTH).status_code == 200
    assert relay.c.get("/ready").status_code == 200


def test_item_not_found_is_404_without_reauth(relay):
    r = relay.c.get(url("does-not-exist", "password"), headers=AUTH)
    assert r.status_code == 404
    assert ["login"] not in [c["argv"] for c in relay.env.calls()[3:]]


def test_wrong_vault_is_500_without_reauth(relay_factory, monkeypatch):
    monkeypatch.setenv("PROTON_PASS_VAULT", "NoSuchVault")
    r = relay_factory()
    assert r.c.get(url("smtp-relay", "password"), headers=AUTH).status_code == 500
    assert ["login"] not in [c["argv"] for c in r.env.calls()[3:]]


def test_garbage_output_is_502(relay_factory, monkeypatch):
    monkeypatch.setenv("MOCK_GARBAGE_TITLE", "smtp-relay")
    r = relay_factory()
    assert r.c.get(url("smtp-relay", "password"), headers=AUTH).status_code == 502


def test_timeout_is_504_and_lock_released(relay_factory, monkeypatch):
    monkeypatch.setenv("PASS_CLI_TIMEOUT_SECONDS", "1")
    monkeypatch.setenv("MOCK_HANG_TITLE", "cloudflare-api")
    r = relay_factory()
    t0 = time.time()
    assert r.c.get(url("cloudflare-api", "token"), headers=AUTH).status_code == 504
    assert time.time() - t0 < 5
    assert r.c.get(url("smtp-relay", "password"), headers=AUTH).status_code == 200


# ── 6. Argv safety, agent reason, cache ──────────────────────────────────────

@pytest.mark.parametrize("title", ["-leading-dash", "spaces and ?query=1#frag", "ümlaut ✓"])
def test_titles_passed_verbatim(relay, title):
    (relay.env.fixtures / f"{title}.json").write_text((HERE / "fixtures" / "smtp-relay.json").read_text())
    assert relay.c.get(url(title, "password"), headers=AUTH).status_code == 200
    view = [c["argv"] for c in relay.env.calls() if c["argv"][:2] == ["item", "view"]][-1]
    assert f"--item-title={title}" in view and "--vault-name=Homelab" in view


def test_agent_reason_per_call_and_truncated(relay):
    relay.c.get(url("smtp-relay", "password"), headers=AUTH)
    long_title = "x" * 400
    relay.c.get(url(long_title, "password"), headers=AUTH)
    reasons = [c["reason"] for c in relay.env.calls() if c["argv"][:2] == ["item", "view"]]
    assert "smtp-relay" in reasons[0]
    assert len(reasons[1]) == 300
    assert all(c["reason"] is None for c in relay.env.calls() if c["argv"][0] != "item")


def test_operator_agent_reason_wins(relay_factory, monkeypatch):
    monkeypatch.setenv("PROTON_PASS_AGENT_REASON", "ops-defined reason")
    r = relay_factory()
    r.c.get(url("smtp-relay", "password"), headers=AUTH)
    assert r.env.calls()[-1]["reason"] == "ops-defined reason"


def test_cache_dedupes_item_views(relay_factory, monkeypatch):
    monkeypatch.setenv("CACHE_TTL_SECONDS", "60")
    r = relay_factory()
    for f in ("password", "username", "api_key", "region"):
        assert r.c.get(url("smtp-relay", f), headers=AUTH).status_code == 200
    assert sum(c["argv"][:2] == ["item", "view"] for c in r.env.calls()) == 1


def test_cache_disabled(relay):
    for f in ("password", "username"):
        relay.c.get(url("smtp-relay", f), headers=AUTH)
    assert sum(c["argv"][:2] == ["item", "view"] for c in relay.env.calls()) == 2


# ── 7. Logs ──────────────────────────────────────────────────────────────────

def test_no_secret_values_in_logs(relay, caplog):
    caplog.set_level("DEBUG")
    relay.env.flag("expire_next")
    for t, q, _ in CASES:
        relay.c.get(url(t, q), headers=AUTH)
    assert "Served smtp-relay/password" in caplog.text          # caplog really captures relay logs
    assert {"cf-api-token", "login-password-VALUE", "4111111111111111"} <= secret_values()
    leaked = [v for v in secret_values() if v in caplog.text]
    assert not leaked, leaked


def test_stderr_condensed(relay):
    raw = ("\x1b[2m2026-09-23T10:27:07Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2mpass-cli/src/main.rs\x1b[0m: no session\n"
           "Error: Error getting base dir\n\nCaused by:\n    Session directory is accessible by group or others\n\n"
           "Stack backtrace:\n   0: anyhow::error::msg\n")
    out = relay.mod.condense(raw)
    assert out == "Error: Error getting base dir | Caused by: | Session directory is accessible by group or others"


# ── 8. Concurrency under a real uvicorn server ───────────────────────────────

def _burst(module, mock_env, tmp_path, n=16):
    env = dict(os.environ, MOCK_LATENCY="0.15", CACHE_TTL_SECONDS="0")
    srv = Server(module, env, tmp_path / f"{module}.log")
    try:
        assert srv.wait_ready(), srv.stop()
        before = mock_env.overlaps()
        queries = [("smtp-relay", "password"), ("smtp-relay", "api_key"), ("cloudflare-api", "token"), ("just-a-note", "note")]
        with httpx.Client(base_url=srv.url, headers=AUTH, timeout=60) as c, ThreadPoolExecutor(n) as pool:
            codes = list(pool.map(lambda i: c.get(url(*queries[i % 4])).status_code, range(n)))
        return codes, mock_env.overlaps() - before, srv
    finally:
        log = srv.stop()
        srv.log_text = log


def test_concurrent_burst_new_relay(mock_env, tmp_path):
    codes, overlaps, srv = _burst("app", mock_env, tmp_path)
    print(f"\nNEW relay: statuses={sorted(set(codes))} overlaps={overlaps}")
    assert overlaps == 0
    assert codes == [200] * len(codes)
    assert not [v for v in secret_values() if v in srv.log_text]


@OLD
def test_concurrent_burst_old_relay_races(mock_env, tmp_path):
    codes, overlaps, _ = _burst("original_main", mock_env, tmp_path)
    print(f"\nOLD relay: statuses={ {c: codes.count(c) for c in set(codes)} } overlaps={overlaps}")
    assert overlaps > 0   # concurrent pass-cli processes on one session


def _real_version():
    try:
        out = subprocess.run([str(REAL_BIN), "--version"], capture_output=True, text=True, timeout=10).stdout
    except OSError:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(map(int, m.groups())) if m else None


NEEDS_24 = pytest.mark.skipif((_real_version() or (0,)) < (2, 4, 0),
                              reason="pass-cli on PATH is < 2.4.0 (no session-dir permission check)")


# ── 9. Real pass-cli 2.4.1 binary ────────────────────────────────────────────

@pytest.fixture
def real_env(tmp_path, monkeypatch):
    if not REAL_BIN.exists():
        pytest.skip("real pass-cli binary not available")
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
        "BRIDGE_TOKEN": TOKEN,
        "PROTON_PASS_SESSION_DIR": str(sess),
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return sess


@NEEDS_24
def test_real_binary_rejects_loose_session_dir_until_relay_fixes_it(real_env):
    import conftest
    mod = conftest.load("app")
    rc, _, err = mod.pass_cli(["info"])
    assert rc == 1 and "accessible by group or others" in err     # 2.4.1 refuses 2770
    mod.prepare_session_dir()
    assert stat.S_IMODE((real_env / ".session").stat().st_mode) == 0o2700   # setgid kept, g/o cleared
    rc, _, err = mod.pass_cli(["info"])
    assert rc == 1 and mod.NO_SESSION in err                      # now past the base-dir check


def test_real_binary_symlinked_session_dir_fails_fast(real_env, tmp_path, monkeypatch):
    import conftest
    link = tmp_path / "linked"
    link.symlink_to(real_env)
    monkeypatch.setenv("PROTON_PASS_SESSION_DIR", str(link))
    mod = conftest.load("app")
    with pytest.raises(RuntimeError, match="symlink"):
        mod.prepare_session_dir()


@pytest.mark.parametrize("title", ["-leading-dash", "spaces ?q=1#f", "a/b"])
def test_real_binary_accepts_relay_argv(real_env, title):
    import conftest
    mod = conftest.load("app")
    mod.prepare_session_dir()
    rc, _, err = mod._view(title)
    assert rc == 1 and mod.NO_SESSION in err     # clap accepted the argv; failed only on auth


def test_real_binary_startup_exits_cleanly_without_proton(real_env, tmp_path):
    srv = Server("app", dict(os.environ), tmp_path / "real.log")
    srv.proc.wait(60)
    log = srv.stop()
    print("\n" + log)
    assert srv.proc.returncode != 0
    assert "tightening to 2700" in log
    assert "pass-cli login failed (exit 1): Error: Error in personal access token login flow" in log
    assert "Error creating personal access token session" in log   # got past PAT parsing into muon 3 networking
    assert "Initial authentication failed" in log
    assert "\x1b[" not in log and "Stack backtrace" not in log
    assert "a" * 64 not in log                     # PAT never logged


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
    print(f"\nNO-LOCK mutant: statuses={ {c: codes.count(c) for c in set(codes)} } overlaps={overlaps}")
    assert overlaps > 0, "the burst test would not detect a missing lock"
