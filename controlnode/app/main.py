"""
ControlNode — DFSha (Hito 2)

Servicio de metadatos: namespace (directorios/archivos), asignacion de
bloques a DataNodes, y registro/heartbeat de DataNodes.

Guarda todo en memoria (dict), protegido con un lock simple -- suficiente
para la demo de este hito. La persistencia en disco/replica se deja para
el Hito 3 (Alta Disponibilidad).
"""
import time
import uuid
import threading
from itertools import count
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

app = FastAPI(title="DFSha ControlNode", version="0.2.0")
security = HTTPBasic()

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------
BLOCK_SIZE = 4 * 1024 * 1024          # 4 MB por bloque (fijo para este hito)
HEARTBEAT_TIMEOUT = 15                # segundos sin heartbeat -> DataNode inactivo

# Usuarios validos (demo). Hito 3 agrega hashing / 2FA / API keys.
USERS = {
    "vale": "vale123",
    "admin": "admin123",
}

# ---------------------------------------------------------------------------
# Estado en memoria
# ---------------------------------------------------------------------------
lock = threading.Lock()

directories = {"/"}                    # set de paths de directorios existentes
files: Dict[str, dict] = {}            # path -> {"size", "owner", "blocks":[{block_id, datanode_id}]}
datanodes: Dict[str, dict] = {}        # datanode_id -> {"url", "last_heartbeat"}
_rr_counter = count()                  # contador para el round-robin


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class MkdirRequest(BaseModel):
    path: str


class CreateFileRequest(BaseModel):
    path: str
    size: int


class BlockPlan(BaseModel):
    block_id: str
    seq: int
    datanode_id: str
    datanode_url: str


class CreateFileResponse(BaseModel):
    path: str
    block_size: int
    blocks: List[BlockPlan]


class LocateResponse(BaseModel):
    path: str
    size: int
    blocks: List[BlockPlan]


class RegisterRequest(BaseModel):
    datanode_id: str
    url: str


class HeartbeatRequest(BaseModel):
    datanode_id: str


# ---------------------------------------------------------------------------
# Auth basica (RF: login usuario/password)
# ---------------------------------------------------------------------------
def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    expected = USERS.get(credentials.username)
    if expected is None or expected != credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o password invalidos",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.post("/auth/login")
def login(user: str = Depends(get_current_user)):
    return {"status": "ok", "user": user}


# ---------------------------------------------------------------------------
# Helpers de namespace
# ---------------------------------------------------------------------------
def _normalize(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def _parent(path: str) -> str:
    if path == "/":
        return "/"
    parent = path.rsplit("/", 1)[0]
    return parent if parent else "/"


def _active_datanodes() -> List[str]:
    now = time.time()
    return [
        dn_id for dn_id, info in datanodes.items()
        if now - info["last_heartbeat"] <= HEARTBEAT_TIMEOUT
    ]


def _pick_datanode_round_robin() -> str:
    active = sorted(_active_datanodes())
    if not active:
        raise HTTPException(status_code=503, detail="No hay DataNodes activos registrados")
    idx = next(_rr_counter) % len(active)
    return active[idx]


# ---------------------------------------------------------------------------
# Gestion del sistema de archivos (RF1)
# ---------------------------------------------------------------------------
@app.get("/fs/ls")
def ls(path: str = "/", user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        if path != "/" and path not in directories:
            raise HTTPException(status_code=404, detail="Directorio no existe")

        prefix = "" if path == "/" else path
        child_dirs = set()
        child_files = []

        for d in directories:
            if d == path:
                continue
            if _parent(d) == path:
                child_dirs.add(d.rsplit("/", 1)[-1])

        for f, meta in files.items():
            if _parent(f) == path:
                child_files.append({"name": f.rsplit("/", 1)[-1], "size": meta["size"]})

        return {"path": path, "directories": sorted(child_dirs), "files": child_files}


@app.post("/fs/mkdir")
def mkdir(req: MkdirRequest, user: str = Depends(get_current_user)):
    path = _normalize(req.path)
    with lock:
        if path in directories:
            raise HTTPException(status_code=409, detail="El directorio ya existe")
        if _parent(path) not in directories:
            raise HTTPException(status_code=404, detail="El directorio padre no existe")
        directories.add(path)
    return {"status": "ok", "path": path}


@app.delete("/fs/rmdir")
def rmdir(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        if path == "/":
            raise HTTPException(status_code=400, detail="No se puede borrar la raiz")
        if path not in directories:
            raise HTTPException(status_code=404, detail="Directorio no existe")
        has_children = any(_parent(d) == path for d in directories) or \
            any(_parent(f) == path for f in files)
        if has_children:
            raise HTTPException(status_code=409, detail="Directorio no esta vacio")
        directories.remove(path)
    return {"status": "ok"}


@app.delete("/fs/rm")
def rm(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        meta = files.pop(path, None)
        if meta is None:
            raise HTTPException(status_code=404, detail="Archivo no existe")
    # Mejor esfuerzo: pedirle a cada DataNode que borre su bloque.
    import httpx
    for b in meta["blocks"]:
        dn = datanodes.get(b["datanode_id"])
        if dn:
            try:
                httpx.delete(f"{dn['url']}/block/{b['block_id']}", timeout=3)
            except Exception:
                pass
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Transferencia de archivos (RF2) -- planificacion de bloques
# ---------------------------------------------------------------------------
@app.post("/fs/create", response_model=CreateFileResponse)
def create_file(req: CreateFileRequest, user: str = Depends(get_current_user)):
    path = _normalize(req.path)
    with lock:
        if _parent(path) not in directories:
            raise HTTPException(status_code=404, detail="El directorio padre no existe")

        num_blocks = max(1, -(-req.size // BLOCK_SIZE))  # ceil div
        blocks = []
        for seq in range(num_blocks):
            dn_id = _pick_datanode_round_robin()
            block_id = str(uuid.uuid4())
            blocks.append({"block_id": block_id, "seq": seq, "datanode_id": dn_id})

        files[path] = {"size": req.size, "owner": user, "blocks": blocks}

        plan = [
            BlockPlan(
                block_id=b["block_id"], seq=b["seq"], datanode_id=b["datanode_id"],
                datanode_url=datanodes[b["datanode_id"]]["url"],
            )
            for b in blocks
        ]
    return CreateFileResponse(path=path, block_size=BLOCK_SIZE, blocks=plan)


@app.get("/fs/locate", response_model=LocateResponse)
def locate(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        meta = files.get(path)
        if meta is None:
            raise HTTPException(status_code=404, detail="Archivo no existe")
        plan = [
            BlockPlan(
                block_id=b["block_id"], seq=b["seq"], datanode_id=b["datanode_id"],
                datanode_url=datanodes[b["datanode_id"]]["url"],
            )
            for b in sorted(meta["blocks"], key=lambda b: b["seq"])
        ]
    return LocateResponse(path=path, size=meta["size"], blocks=plan)


# ---------------------------------------------------------------------------
# Registro y heartbeat de DataNodes
# ---------------------------------------------------------------------------
@app.post("/datanode/register")
def register_datanode(req: RegisterRequest):
    with lock:
        datanodes[req.datanode_id] = {"url": req.url, "last_heartbeat": time.time()}
    return {"status": "ok"}


@app.post("/datanode/heartbeat")
def heartbeat(req: HeartbeatRequest):
    with lock:
        if req.datanode_id not in datanodes:
            raise HTTPException(status_code=404, detail="DataNode no registrado")
        datanodes[req.datanode_id]["last_heartbeat"] = time.time()
    return {"status": "ok"}


@app.get("/datanode/list")
def list_datanodes(user: str = Depends(get_current_user)):
    with lock:
        active = set(_active_datanodes())
        return [
            {"datanode_id": k, "url": v["url"], "active": k in active}
            for k, v in datanodes.items()
        ]


@app.get("/health")
def health():
    return {"status": "ok"}