#!/usr/bin/env python3
"""
Mock pass-cli 2.5.x for proton-relay tests.

Vault contents: every tests/fixtures/*.json except folders.json is one item, in the exact shape of
`pass-cli item view --output json` (generated from pass-cli's own serde models). An item's folder is its
"folder_id" (absent = vault root). folders.json is the `pass-cli folder list --output json` output.
Error strings are copied from pass-cli 2.5.1 source / observed from the real binary.

Session race model: Proton refresh tokens rotate, so two pass-cli processes on one session at once
clobber each other. Any overlapping invocation is recorded, invalidates the session and fails.

Control files in $MOCK_DIR:
  session       exists => logged in
  expire_next   next data command expires the session first (then the flag is removed)
  login_fail    `login` fails
  stale         refresh never persisted (pass-cli 2.3/2.4 bug): data commands fail while `info` succeeds;
                `login` clears it
  broken        every data command fails, even after a fresh login
  bad_list      `item list` prints valid JSON in the wrong shape
  calls.jsonl   one JSON line per invocation (argv + relevant env)
  overlaps      count of detected concurrent invocations
"""
import json
import os
import sys
import time
from pathlib import Path

M = Path(os.environ["MOCK_DIR"])
FIXTURES = Path(os.environ["MOCK_FIXTURES"])
VAULT = os.environ.get("MOCK_VAULT", "Homelab")
LATENCY = float(os.environ.get("MOCK_LATENCY", "0"))
HANG_TITLE = os.environ.get("MOCK_HANG_TITLE")
GARBAGE_TITLE = os.environ.get("MOCK_GARBAGE_TITLE")

ANSI_ERR = "\x1b[2m2026-10-29T10:27:07.354009Z\x1b[0m \x1b[31mERROR\x1b[0m \x1b[2mpass-cli/src/main.rs\x1b[0m\x1b[2m:\x1b[0m\x1b[2m360:\x1b[0m Command is not logout there is no session"
BACKTRACE = "\nStack backtrace:\n   0: anyhow::error::<impl anyhow::Error>::msg\n   1: pass_cli::run::{{closure}}\n"
# `item list` item_type values (pass-cli item/list.rs ItemType, snake_case)
LIST_TYPES = {"Login": "login", "Note": "note", "Custom": "custom", "SshKey": "ssh_key", "Alias": "alias",
              "CreditCard": "credit_card", "Identity": "identity", "Wifi": "wifi"}


def fail(msg: str, code: int = 1):
    bt = BACKTRACE if os.environ.get("RUST_BACKTRACE", "1") != "0" else ""
    sys.stderr.write(f"Error: {msg}\n{bt}")
    sys.exit(code)


def no_session():
    sys.stderr.write(ANSI_ERR + "\n")
    fail("This operation requires an authenticated client")


def record(argv):
    entry = {
        "argv": argv,
        "t": time.time(),
        "key_provider": os.environ.get("PROTON_PASS_KEY_PROVIDER"),
        "backtrace": os.environ.get("RUST_BACKTRACE"),
        "reason": os.environ.get("PROTON_PASS_AGENT_REASON"),
        "has_pat": bool(os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN")),
    }
    with open(M / "calls.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def bump(name: str):
    p = M / name
    n = int(p.read_text() or 0) if p.exists() else 0   # best-effort; tests only assert > 0 or == 0
    p.write_text(str(n + 1))


def flag(name: str) -> bool:
    return (M / name).exists()


def arg(argv, name):
    for a in argv:
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
    return None


def items():
    for f in sorted(FIXTURES.glob("*.json")):
        if f.name != "folders.json":
            yield json.loads(f.read_text())


def preflight(argv, vault_err: str):
    """Session and vault checks every data command performs, in pass-cli's order."""
    if not flag("session"):
        no_session()
    if flag("stale"):
        sys.stderr.write(
            "2026-09-30T00:49:35.696490Z ERROR pass-auth/src/store.rs:199: Error serializing auth: "
            "Error saving session to storage\n\nCaused by:\n    0: Error opening temp session file\n"
            "    1: background task failed\n")
        fail(f"Error finding vault [{arg(argv, 'vault-name')}]: Error listing vaults")
    if flag("expire_next"):
        (M / "expire_next").unlink()
        (M / "session").unlink(missing_ok=True)
        no_session()
    if flag("broken"):
        fail("Error listing items\n\nCaused by:\n    0: Error fetching items\n    1: Error sending request\n"
             "    2: upstream connect error")
    if arg(argv, "vault-name") != VAULT:
        fail(vault_err.format(v=arg(argv, "vault-name")))


def item_list(argv):
    preflight(argv, "Error finding vault\n\nCaused by:\n    Could not find vault {v}")
    if flag("bad_list"):
        print('{"unexpected": []}')
        return
    state = arg(argv, "filter-state")
    out = []
    for d in items():
        it = d["item"]
        if state and it["state"].lower() != state:
            continue
        kind = next(iter(it["content"]["content"]))
        summary = {k: it[k] for k in ("id", "share_id", "vault_id", "state", "flags", "create_time", "modify_time")}
        if it.get("folder_id"):
            summary["folder_id"] = it["folder_id"]
        summary.update(title=it["content"]["title"], item_type=LIST_TYPES[kind])
        out.append(summary)
    print(json.dumps({"items": out}, indent=2))


def folder_list(argv):
    preflight(argv, "Error finding vault [{v}]: Could not find vault {v}")
    print((FIXTURES / "folders.json").read_text().rstrip("\n"))


def item_view(argv):
    preflight(argv, "Error finding vault [{v}]: Could not find vault {v}")
    item_id = arg(argv, "item-id")
    found = next((d for d in items() if d["item"]["id"] == item_id), None)
    if found is None:
        fail("Error retrieving item\n\nCaused by:\n    0: Error fetching item\n"
             "    1: Could not perform operation. Reason: NotExists")
    title = found["item"]["content"]["title"]
    if title == HANG_TITLE:
        (M / "inflight").rmdir()  # a SIGKILLed process must not poison later calls
        time.sleep(3600)
    if title == GARBAGE_TITLE:
        print("{not json")
        return
    print(json.dumps(found, indent=2))


COMMANDS = {("item", "list"): item_list, ("item", "view"): item_view, ("folder", "list"): folder_list}


def main():
    argv = sys.argv[1:]
    record(argv)

    # Concurrency detection: an atomic mkdir marks "a pass-cli process is using the session".
    marker = M / "inflight"
    try:
        marker.mkdir()
    except FileExistsError:
        bump("overlaps")
        (M / "session").unlink(missing_ok=True)   # rotated refresh token clobbered
        no_session()
    try:
        if LATENCY:
            time.sleep(LATENCY)
        if argv[:1] == ["logout"]:
            (M / "session").unlink(missing_ok=True)
            print("Executing force logout\nSuccessfully performed force logout")
        elif argv[:1] == ["login"]:
            if not os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN"):
                fail("web login is not possible in this environment")
            if flag("login_fail"):
                fail("Error in personal access token login flow\n\nCaused by:\n"
                     "    0: Error creating personal access token session\n    1: Too many recent logins")
            (M / "session").write_text("1")
            (M / "stale").unlink(missing_ok=True)
            print("Successfully logged in as noreply@nebulahvelvet.no")
        elif argv[:1] == ["info"]:
            if not flag("session"):
                no_session()
            print("Session: valid")
        elif tuple(argv[:2]) in COMMANDS:
            COMMANDS[tuple(argv[:2])](argv)
        else:
            fail(f"mock: unsupported command {argv}", 2)
    finally:
        try:
            marker.rmdir()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()