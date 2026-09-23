import importlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

HERE = Path(__file__).parent
ROOT = HERE.parent / "bridge"
sys.path.insert(0, str(ROOT))

TOKEN = "test-bridge-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
import shutil as _sh
# Real pass-cli for integration tests: $PASS_CLI_REAL_BIN, else pass-cli on PATH, else those tests skip.
REAL_BIN = Path(os.environ.get("PASS_CLI_REAL_BIN") or _sh.which("pass-cli") or "/nonexistent")


def _calls(mdir: Path):
    f = mdir / "calls.jsonl"
    return [json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []


@pytest.fixture
def mock_env(tmp_path, monkeypatch):
    mdir = tmp_path / "mock"
    mdir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    wrapper = bindir / "pass-cli"
    wrapper.write_text(f'#!/bin/sh\nexec {sys.executable} {HERE / "mock_pass_cli.py"} "$@"\n')
    wrapper.chmod(0o755)
    fixtures = tmp_path / "fixtures"
    shutil.copytree(HERE / "fixtures", fixtures)
    session = tmp_path / "session"
    session.mkdir()
    env = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "MOCK_DIR": str(mdir),
        "MOCK_FIXTURES": str(fixtures),
        "PROTON_PASS_PERSONAL_ACCESS_TOKEN": "pst_test::key",
        "PROTON_PASS_VAULT": "Homelab",
        "BRIDGE_TOKEN": TOKEN,
        "PROTON_PASS_SESSION_DIR": str(session),
        "CACHE_TTL_SECONDS": "0",
        "RUST_BACKTRACE": "1",  # prove the relay forces it off for children
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    for k in ("PROTON_PASS_AGENT_REASON", "ALLOWED_ITEM_TYPES", "MOCK_LATENCY",
              "MOCK_HANG_TITLE", "MOCK_GARBAGE_TITLE", "PASS_CLI_TIMEOUT_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    return SimpleNamespace(
        dir=mdir, fixtures=fixtures, session=session, tmp=tmp_path, bindir=bindir,
        calls=lambda: _calls(mdir),
        flag=lambda name: (mdir / name).write_text("1"),
        overlaps=lambda: int((mdir / "overlaps").read_text()) if (mdir / "overlaps").exists() else 0,
    )


def load(name):
    mod = sys.modules.get(name)
    return importlib.reload(mod) if mod else importlib.import_module(name)


@pytest.fixture
def relay_factory(mock_env):
    """Start the app (lifespan included) for a given module after env tweaks."""
    stack = []

    def make(module="app"):
        mod = load(module)
        client = TestClient(mod.app)
        client.__enter__()
        stack.append(client)
        return SimpleNamespace(c=client, mod=mod, env=mock_env)

    yield make
    for client in reversed(stack):
        client.__exit__(None, None, None)


@pytest.fixture
def relay(relay_factory):
    return relay_factory("app")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A real uvicorn process — for concurrency and startup-failure tests."""

    def __init__(self, module, env, log_path):
        self.port = free_port()
        self.log_path = log_path
        self.log = open(log_path, "w")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", f"{module}:app", "--port", str(self.port), "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )
        self.url = f"http://127.0.0.1:{self.port}"

    def wait_ready(self, timeout=30):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if httpx.get(self.url + "/health", timeout=1).status_code == 200:
                    return True
            except httpx.HTTPError:
                time.sleep(0.1)
        return False

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.log.close()
        return Path(self.log_path).read_text()
