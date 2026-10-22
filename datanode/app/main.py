"""DataNode: almacena bloques cifrados, replica y reporta su salud al ControlNode."""
import asyncio
import base64
import hashlib
import hmac
import os
import time
from contextlib import asynccontextmanager

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

CONTROL_URL = os.environ.get("CONTROL_URL", "http://localhost:8000")
DATANODE_ID = os.environ.get("DATANODE_ID", "dn1")
DATANODE_URL = os.environ.get("DATANODE_URL", "http://localhost:8001")
DATANODE_INTERNAL_URL = os.environ.get("DATANODE_INTERNAL_URL", DATANODE_URL)
BLOCK_DIR = os.environ.get("BLOCK_DIR", "./blocks")
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "5"))
INTERNAL_SECRET = os.environ.get("DFSHA_INTERNAL_SECRET", "dfsha-local-development-secret-change-me")
configured_block_key = os.environ.get("DFSHA_BLOCK_ENCRYPTION_KEY")
if configured_block_key:
    block_key = base64.urlsafe_b64decode(configured_block_key.encode("ascii"))
    if len(block_key) != 32:
        raise ValueError("DFSHA_BLOCK_ENCRYPTION_KEY debe codificar exactamente 32 bytes")
else:
    block_key = hashlib.sha256((INTERNAL_SECRET + ":blocks").encode()).digest()
block_cipher = AESGCM(block_key)

os.makedirs(BLOCK_DIR, exist_ok=True)


async def _register_with_retry():
    async with httpx.AsyncClient() as client:
        for attempt in range(30):
            try:
                r = await client.post(
                    f"{CONTROL_URL}/datanode/register",
                    json={"datanode_id": DATANODE_ID, "url": DATANODE_URL, "internal_url": DATANODE_INTERNAL_URL},
                    headers={"X-Internal-Secret": INTERNAL_SECRET},
                    timeout=3,
                )
                r.raise_for_status()
                print(f"[{DATANODE_ID}] registrado en ControlNode")
                return
            except Exception as e:
                print(f"[{DATANODE_ID}] intento {attempt}: no pude registrarme ({e}), reintentando...")
                await asyncio.sleep(2)
        print(f"[{DATANODE_ID}] no se pudo registrar tras varios intentos")


async def _heartbeat_loop():
    async with httpx.AsyncClient() as client:
        while True:
            try:
                response = await client.post(
                    f"{CONTROL_URL}/datanode/heartbeat",
                    json={"datanode_id": DATANODE_ID},
                    headers={"X-Internal-Secret": INTERNAL_SECRET},
                    timeout=3,
                )
                if response.status_code == 404:
                    await client.post(
                        f"{CONTROL_URL}/datanode/register",
                        json={
                            "datanode_id": DATANODE_ID,
                            "url": DATANODE_URL,
                            "internal_url": DATANODE_INTERNAL_URL,
                        },
                        headers={"X-Internal-Secret": INTERNAL_SECRET},
                        timeout=3,
                    )
                else:
                    response.raise_for_status()
            except Exception as e:
                print(f"[{DATANODE_ID}] heartbeat fallido: {e}")
            await asyncio.sleep(HEARTBEAT_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _register_with_retry()
    task = asyncio.create_task(_heartbeat_loop())
    yield
    task.cancel()


app = FastAPI(title=f"DFSha DataNode ({DATANODE_ID})", version="0.3.0", lifespan=lifespan)


def _block_path(block_id: str) -> str:
    # block_id es un uuid generado por el ControlNode -- seguro para usar como nombre de archivo.
    return os.path.join(BLOCK_DIR, block_id)


def _verify_block_token(block_id: str, token: str | None) -> bool:
    expected = hmac.new(INTERNAL_SECRET.encode(), block_id.encode(), hashlib.sha256).hexdigest()
    return bool(token) and hmac.compare_digest(token, expected)


def _encrypt_block(block_id: str, data: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = block_cipher.encrypt(nonce, data, block_id.encode())
    return b"DFSB1" + nonce + ciphertext


def _decrypt_block(block_id: str, data: bytes) -> bytes:
    if not data.startswith(b"DFSB1"):
        return data
    return block_cipher.decrypt(data[5:17], data[17:], block_id.encode())


@app.put("/block/{block_id}")
async def put_block(block_id: str, request: Request):
    if not _verify_block_token(block_id, request.headers.get("X-Block-Token")):
        raise HTTPException(status_code=401, detail="Token de bloque invalido")
    data = await request.body()
    path = _block_path(block_id)
    temporary = path + ".tmp"
    with open(temporary, "wb") as f:
        f.write(_encrypt_block(block_id, data))
    os.replace(temporary, path)
    return {"status": "ok", "block_id": block_id, "bytes": len(data)}


@app.get("/block/{block_id}")
def get_block(block_id: str, request: Request):
    if not _verify_block_token(block_id, request.headers.get("X-Block-Token")):
        raise HTTPException(status_code=401, detail="Token de bloque invalido")
    path = _block_path(block_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Bloque no existe")
    with open(path, "rb") as f:
        stored = f.read()
    data = _decrypt_block(block_id, stored)
    if not stored.startswith(b"DFSB1"):
        temporary = path + ".tmp"
        with open(temporary, "wb") as f:
            f.write(_encrypt_block(block_id, data))
        os.replace(temporary, path)
    return Response(content=data, media_type="application/octet-stream")


@app.delete("/block/{block_id}")
def delete_block(block_id: str, request: Request):
    if not _verify_block_token(block_id, request.headers.get("X-Block-Token")):
        raise HTTPException(status_code=401, detail="Token de bloque invalido")
    path = _block_path(block_id)
    if os.path.exists(path):
        os.remove(path)
    return {"status": "ok"}


@app.get("/block/{block_id}/status")
def block_status(block_id: str, request: Request):
    if not _verify_block_token(block_id, request.headers.get("X-Block-Token")):
        raise HTTPException(status_code=401, detail="Token de bloque invalido")
    path = _block_path(block_id)
    exists = os.path.exists(path)
    size = None
    if exists:
        with open(path, "rb") as f:
            size = len(_decrypt_block(block_id, f.read()))
    return {
        "block_id": block_id,
        "exists": exists,
        "size": size,
    }


@app.get("/health")
def health():
    return {"status": "ok", "datanode_id": DATANODE_ID}