"""Levanta un cluster DFSha local (1 ControlNode + 3 DataNodes) para las pruebas.

No necesita Docker: arranca cada nodo con uvicorn en un puerto distinto y con
carpetas temporales. Si existe certs/ (scripts/gen_certs.sh) y DFSHA_TEST_TLS=1,
todo corre por HTTPS.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
BASE_PORT = int(os.environ.get("DFSHA_TEST_PORT", "18000"))
USE_TLS = os.environ.get("DFSHA_TEST_TLS") == "1"
SCHEME = "https" if USE_TLS else "http"
CERTS = ROOT / "certs"
SECRET = "secreto-de-pruebas"
if USE_TLS:
    # para que el httpx de las propias pruebas confie en nuestra CA
    os.environ["SSL_CERT_FILE"] = str(CERTS / "ca.crt")


class Cluster:
    def __init__(self):
        self.workdir = Path(tempfile.mkdtemp(prefix="dfsha-test-"))
        self.control_url = f"{SCHEME}://localhost:{BASE_PORT}"
        self.procs = {}
        self.env_base = dict(os.environ)
        self.env_base.update({
            "DFSHA_INTERNAL_SECRET": SECRET,
            "PYTHONUNBUFFERED": "1",
        })
        if USE_TLS:
            self.env_base["SSL_CERT_FILE"] = str(CERTS / "ca.crt")

    def _uvicorn(self, app_dir, port, env, name):
        cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"]
        if USE_TLS:
            cmd += ["--ssl-certfile", str(CERTS / "node.crt"), "--ssl-keyfile", str(CERTS / "node.key")]
        log = open(self.workdir / f"{name}.log", "ab")
        self.procs[name] = subprocess.Popen(cmd, cwd=ROOT / app_dir, env=env, stdout=log, stderr=log)

    def start_control(self):
        env = dict(self.env_base)
        env.update({
            "DFSHA_STATE_FILE": str(self.workdir / "control" / "state.json"),
            "REPLICATION_FACTOR": "2",
            "HEARTBEAT_TIMEOUT": "4",
            "REPAIR_INTERVAL": "2",
            "ORPHAN_GRACE": "1",
        })
        self._uvicorn("controlnode", BASE_PORT, env, "control")

    def start_datanode(self, n):
        port = BASE_PORT + n
        env = dict(self.env_base)
        env.update({
            "CONTROL_URL": self.control_url,
            "DATANODE_ID": f"dn{n}",
            "DATANODE_URL": f"{SCHEME}://localhost:{port}",
            "BLOCK_DIR": str(self.block_dir(n)),
            "HEARTBEAT_INTERVAL": "1",
        })
        self._uvicorn("datanode", port, env, f"dn{n}")

    def block_dir(self, n):
        return self.workdir / f"blocks{n}"

    def stop(self, name):
        proc = self.procs.pop(name, None)
        if proc:
            proc.send_signal(signal.SIGKILL)  # simula una caida abrupta
            proc.wait()

    def wait_active(self, expected, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = httpx.get(f"{self.control_url}/datanode/list", auth=("admin", "admin123"), timeout=2)
                if r.status_code == 200 and sum(n["active"] for n in r.json()) == expected:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"El cluster no llego a {expected} DataNodes activos")

    def shutdown(self):
        for name in list(self.procs):
            self.stop(name)
        shutil.rmtree(self.workdir, ignore_errors=True)


@pytest.fixture(scope="session")
def cluster():
    if USE_TLS and not (CERTS / "node.crt").exists():
        pytest.skip("Faltan certificados: corre scripts/gen_certs.sh")
    c = Cluster()
    try:
        c.start_control()
        time.sleep(1.5)
        for n in (1, 2, 3):
            c.start_datanode(n)
        c.wait_active(3)
    except Exception:
        c.shutdown()  # no dejar procesos sueltos si el arranque falla
        raise
    yield c
    c.shutdown()


@pytest.fixture(scope="session")
def cli_env(cluster):
    env = dict(cluster.env_base)
    env.update({
        "DFSHA_CONTROL_URL": cluster.control_url,
        "DFSHA_USER": "vale",
        "DFSHA_PASSWORD": "vale123",
    })
    return env


def run_cli(env, *args, check=True):
    result = subprocess.run(
        [sys.executable, str(ROOT / "client" / "dfsha_cli.py"), *args],
        env=env, capture_output=True, text=True, timeout=120,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"CLI fallo {args}: {result.stdout}{result.stderr}")
    return result
