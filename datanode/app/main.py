"""
DataNode -- DFSha (Hito 2)

Servicio de almacenamiento de bloques. Al arrancar se registra contra el
ControlNode y le manda heartbeat periodico. Cada bloque se guarda como un
archivo plano en BLOCK_DIR, nombrado por su block_id (uuid), asi que no hace
falta un indice propio: si el archivo existe, el bloque existe.
"""
import asyncio
import os
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

CONTROL_URL = os.environ.get("CONTROL_URL", "http://localhost:8000")
DATANODE_ID = os.environ.get("DATANODE_ID", "dn1")
DATANODE_URL = os.environ.get("DATANODE_URL", "http://localhost:8001")
BLOCK_DIR = os.environ.get("BLOCK_DIR", "./blocks")
HEARTBEAT_INTERVAL = float(os.environ.get("HEARTBEAT_INTERVAL", "5"))

os.makedirs(BLOCK_DIR, exist_ok=True)


async def _register_with_retry():
    async with httpx.AsyncClient() as client:
        for attempt in range(30):
            try:
                r = await client.post(
                    f"{CONTROL_URL}/datanode/register",
                    json={"datanode_id": DATANODE_ID, "url": DATANODE_URL},
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
                await client.post(
                    f"{CONTROL_URL}/datanode/heartbeat",
                    json={"datanode_id": DATANODE_ID},
                    timeout=3,
                )
            except Exception as e:
                print(f"[{DATANODE_ID}] heartbeat fallido: {e}")
            await asyncio.sleep(HEARTBEAT_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _register_with_retry()
    task = asyncio.create_task(_heartbeat_loop())
    yield
    task.cancel()


app = FastAPI(title=f"DFSha DataNode ({DATANODE_ID})", version="0.2.0", lifespan=lifespan)


def _block_path(block_id: str) -> str:
    # block_id es un uuid generado por el ControlNode -- seguro para usar como nombre de archivo.
    return os.path.join(BLOCK_DIR, block_id)


@app.put("/block/{block_id}")
async def put_block(block_id: str, request: Request):
    data = await request.body()
    with open(_block_path(block_id), "wb") as f:
        f.write(data)
    return {"status": "ok", "block_id": block_id, "bytes": len(data)}


@app.get("/block/{block_id}")
def get_block(block_id: str):
    path = _block_path(block_id)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Bloque no existe")
    with open(path, "rb") as f:
        data = f.read()
    return Response(content=data, media_type="application/octet-stream")


@app.delete("/block/{block_id}")
def delete_block(block_id: str):
    path = _block_path(block_id)
    if os.path.exists(path):
        os.remove(path)
    return {"status": "ok"}


@app.get("/block/{block_id}/status")
def block_status(block_id: str):
    path = _block_path(block_id)
    exists = os.path.exists(path)
    return {
        "block_id": block_id,
        "exists": exists,
        "size": os.path.getsize(path) if exists else None,
    }


@app.get("/health")
def health():
    return {"status": "ok", "datanode_id": DATANODE_ID}