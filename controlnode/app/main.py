"""ControlNode para metadata, autenticacion, coordinacion de bloques y locks."""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
import threading
from contextlib import asynccontextmanager
from itertools import count
from pathlib import Path
from typing import Dict, List, Optional

import pyotp
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, status
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuracion
# ---------------------------------------------------------------------------
BLOCK_SIZE = 4 * 1024 * 1024
HEARTBEAT_TIMEOUT = max(3, int(os.environ.get("HEARTBEAT_TIMEOUT", "15")))
# cada cuanto se revisa si hay bloques con menos replicas de las debidas
REPAIR_INTERVAL = max(2, int(os.environ.get("REPAIR_INTERVAL", "10")))
# un bloque huerfano solo se borra si lleva al menos este tiempo en disco
ORPHAN_GRACE = int(os.environ.get("ORPHAN_GRACE", "120"))
REPLICATION_FACTOR = max(1, int(os.environ.get("REPLICATION_FACTOR", "2")))
HANDLE_TIMEOUT = max(60, int(os.environ.get("HANDLE_TIMEOUT", "300")))
STATE_FILE = Path(os.environ.get("DFSHA_STATE_FILE", "/app/data/state.json"))
INTERNAL_SECRET = os.environ.get("DFSHA_INTERNAL_SECRET", "dfsha-local-development-secret-change-me")
TOTP_ENCRYPTION_KEY = os.environ.get("DFSHA_TOTP_ENCRYPTION_KEY") or base64.urlsafe_b64encode(
    hashlib.sha256(INTERNAL_SECRET.encode()).digest()
).decode("ascii")
totp_cipher = Fernet(TOTP_ENCRYPTION_KEY.encode("ascii"))

# ---------------------------------------------------------------------------
# Estado en memoria
# ---------------------------------------------------------------------------
lock = threading.Lock()
file_io_locks = {}

directories = {"/"}                    # set de paths de directorios existentes
directory_owners: Dict[str, str] = {"/": "admin"}
files: Dict[str, dict] = {}            # path -> {"size", "owner", "blocks":[{block_id, datanode_id}]}
datanodes: Dict[str, dict] = {}        # datanode_id -> {"url", "last_heartbeat"}
users: Dict[str, dict] = {}
api_keys: Dict[str, dict] = {}
open_handles: Dict[str, dict] = {}
file_locks: Dict[str, str] = {}
_rr_counter = count()                  # contador para el round-robin
repair_stats = {"runs": 0, "blocks_repaired": 0, "orphans_deleted": 0, "lost_blocks": 0, "last_run": None}


@asynccontextmanager
async def lifespan(app: FastAPI):
    # hilo de mantenimiento: re-replica bloques y limpia huerfanos
    stop = threading.Event()
    worker = threading.Thread(target=_repair_loop, args=(stop,), daemon=True)
    worker.start()
    yield
    stop.set()


app = FastAPI(title="DFSha ControlNode", version="1.0.0", lifespan=lifespan)
security = HTTPBasic(auto_error=False)
api_key_security = APIKeyHeader(name="X-API-Key", auto_error=False)


def _password_record(password: str, salt: Optional[bytes] = None) -> dict:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return {"salt": salt.hex(), "hash": digest.hex()}


def _verify_password(password: str, record: dict) -> bool:
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(record["salt"]), 310_000
    )
    return hmac.compare_digest(digest.hex(), record["hash"])


def _encrypt_totp(secret: str) -> str:
    return totp_cipher.encrypt(secret.encode()).decode("ascii")


def _decrypt_totp(secret: str) -> str:
    return totp_cipher.decrypt(secret.encode()).decode("ascii")


def _save_state() -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "directories": sorted(directories),
        "directory_owners": directory_owners,
        "files": files,
        "users": users,
        "api_keys": api_keys,
    }
    temporary = STATE_FILE.with_suffix(STATE_FILE.suffix + ".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, STATE_FILE)


def _load_state() -> None:
    global directories, directory_owners, files, users, api_keys
    if STATE_FILE.exists():
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        directories = set(state.get("directories", ["/"]))
        files = state.get("files", {})
        directory_owners = state.get("directory_owners")
        if directory_owners is None:
            directory_owners = {"/": "admin"}
            for directory in directories - {"/"}:
                owners = {
                    meta["owner"] for path, meta in files.items()
                    if path.startswith(directory + "/")
                }
                directory_owners[directory] = next(iter(owners)) if len(owners) == 1 else "admin"
        users = state.get("users", {})
        api_keys = state.get("api_keys", {})
        for username, record in users.items():
            record.setdefault("role", "admin" if username == "admin" else "user")
        for path in directories:
            directory_owners.setdefault(path, "admin")
    else:
        users = {
            "vale": {
                "password": _password_record(os.environ.get("DFSHA_VALE_PASSWORD", "vale123")),
                "totp_secret": None,
                "pending_totp": None,
                "role": "user",
            },
            "admin": {
                "password": _password_record(os.environ.get("DFSHA_ADMIN_PASSWORD", "admin123")),
                "totp_secret": None,
                "pending_totp": None,
                "role": "admin",
            },
        }
        _save_state()


_load_state()


def _is_admin(username: str) -> bool:
    return users.get(username, {}).get("role") == "admin"


def _cleanup_sessions() -> None:
    expired = [
        handle for handle, session in open_handles.items()
        if time.time() - session["last_activity"] > HANDLE_TIMEOUT
    ]
    for handle in expired:
        session = open_handles.pop(handle)
        if file_locks.get(session["path"]) == handle:
            del file_locks[session["path"]]


def _file_io_lock(path: str):
    with lock:
        return file_io_locks.setdefault(path, threading.Lock())


# ---------------------------------------------------------------------------
# Modelos
# ---------------------------------------------------------------------------
class MkdirRequest(BaseModel):
    path: str


class CreateFileRequest(BaseModel):
    path: str
    size: int


class CommitRequest(BaseModel):
    path: str


class BlockPlan(BaseModel):
    block_id: str
    seq: int
    datanode_id: str
    datanode_url: str
    block_token: str
    replicas: List["ReplicaPlan"]


class ReplicaPlan(BaseModel):
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
    internal_url: Optional[str] = None


class HeartbeatRequest(BaseModel):
    datanode_id: str


class OpenRequest(BaseModel):
    path: str
    mode: str = "r"


class HandleRequest(BaseModel):
    handle: str


class ReadRequest(HandleRequest):
    offset: int = 0
    length: int = 4096


class WriteRequest(HandleRequest):
    offset: int = 0
    data: str


class TotpConfirmRequest(BaseModel):
    code: str


class ApiKeyRequest(BaseModel):
    name: str = "cli"


class UserCreateRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Auth basica (RF: login usuario/password)
# ---------------------------------------------------------------------------
def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales invalidas",
        headers={"WWW-Authenticate": "Basic"},
    )


def get_current_user(
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
    api_key: Optional[str] = Depends(api_key_security),
    totp_code: Optional[str] = Header(default=None, alias="X-TOTP-Code"),
) -> str:
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for entry in api_keys.values():
            if hmac.compare_digest(key_hash, entry["hash"]):
                return entry["user"]
        raise _unauthorized()

    if credentials is None:
        raise _unauthorized()
    record = users.get(credentials.username)
    if record is None or not _verify_password(credentials.password, record["password"]):
        raise _unauthorized()
    if record.get("totp_secret"):
        secret = _decrypt_totp(record["totp_secret"])
        if not totp_code or not pyotp.TOTP(secret).verify(totp_code, valid_window=1):
            raise _unauthorized()
    return credentials.username


@app.post("/auth/login")
def login(user: str = Depends(get_current_user)):
    return {"status": "ok", "user": user}


@app.post("/auth/users")
def create_user(req: UserCreateRequest, user: str = Depends(get_current_user)):
    username = req.username.strip()
    if not username or len(username) > 64 or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Usuario invalido o password menor de 8 caracteres")
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Solo admin puede crear usuarios")
    with lock:
        if username in users:
            raise HTTPException(status_code=409, detail="El usuario ya existe")
        users[username] = {
            "password": _password_record(req.password),
            "totp_secret": None,
            "pending_totp": None,
            "role": "user",
        }
        _save_state()
    return {"status": "created", "username": username}


@app.delete("/auth/users/{username}")
def delete_user(username: str, user: str = Depends(get_current_user)):
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Solo admin puede borrar usuarios")
    if username == "admin":
        raise HTTPException(status_code=400, detail="No se puede borrar el usuario admin")
    with lock:
        if username not in users:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        if any(meta["owner"] == username for meta in files.values()):
            raise HTTPException(status_code=409, detail="El usuario todavia posee archivos")
        if any(owner == username for owner in directory_owners.values()):
            raise HTTPException(status_code=409, detail="El usuario todavia posee directorios")
        del users[username]
        for key_id in [key_id for key_id, entry in api_keys.items() if entry["user"] == username]:
            del api_keys[key_id]
        _save_state()
    return {"status": "deleted", "username": username}


@app.post("/auth/totp/setup")
def setup_totp(user: str = Depends(get_current_user)):
    secret = pyotp.random_base32()
    with lock:
        users[user]["pending_totp"] = _encrypt_totp(secret)
        _save_state()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user, issuer_name="DFSha")
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/auth/totp/confirm")
def confirm_totp(req: TotpConfirmRequest, user: str = Depends(get_current_user)):
    with lock:
        record = users[user]
        encrypted_secret = record.get("pending_totp")
        secret = _decrypt_totp(encrypted_secret) if encrypted_secret else None
        if not secret or not pyotp.TOTP(secret).verify(req.code, valid_window=1):
            raise HTTPException(status_code=400, detail="Codigo TOTP invalido")
        record["totp_secret"] = encrypted_secret
        record["pending_totp"] = None
        _save_state()
    return {"status": "ok", "totp_enabled": True}


@app.delete("/auth/totp")
def disable_totp(user: str = Depends(get_current_user)):
    with lock:
        users[user]["totp_secret"] = None
        users[user]["pending_totp"] = None
        _save_state()
    return {"status": "ok", "totp_enabled": False}


@app.post("/auth/api-keys")
def create_api_key(req: ApiKeyRequest, user: str = Depends(get_current_user)):
    raw_key = secrets.token_urlsafe(32)
    key_id = str(uuid.uuid4())
    with lock:
        api_keys[key_id] = {
            "user": user,
            "name": req.name,
            "hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        }
        _save_state()
    return {"key_id": key_id, "api_key": raw_key, "name": req.name}


@app.delete("/auth/api-keys/{key_id}")
def delete_api_key(key_id: str, user: str = Depends(get_current_user)):
    with lock:
        entry = api_keys.get(key_id)
        if entry is None or entry["user"] != user:
            raise HTTPException(status_code=404, detail="API key no encontrada")
        del api_keys[key_id]
        _save_state()
    return {"status": "ok"}


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


def _block_token(block_id: str) -> str:
    return hmac.new(INTERNAL_SECRET.encode(), block_id.encode(), hashlib.sha256).hexdigest()


def _delete_blocks(blocks: List[dict]) -> None:
    import httpx

    for block in blocks:
        for node_id in block.get("replicas", [block["datanode_id"]]):
            node = datanodes.get(node_id)
            if not node:
                continue
            try:
                httpx.delete(
                    f"{node.get('internal_url', node['url'])}/block/{block['block_id']}",
                    headers={"X-Block-Token": _block_token(block["block_id"])},
                    timeout=3,
                )
            except httpx.HTTPError:
                pass


def _block_plan(block: dict, seq: int) -> "BlockPlan":
    active = set(_active_datanodes())
    ids = block.get("replicas", [block["datanode_id"]])
    ordered = sorted(ids, key=lambda node_id: node_id not in active)
    candidates = [node_id for node_id in ordered if node_id in datanodes and node_id in active]
    if not candidates:
        raise HTTPException(status_code=503, detail="No hay replicas activas para un bloque")
    return BlockPlan(
        block_id=block["block_id"],
        seq=seq,
        datanode_id=candidates[0],
        datanode_url=datanodes[candidates[0]]["url"],
        block_token=_block_token(block["block_id"]),
        replicas=[ReplicaPlan(datanode_id=node_id, datanode_url=datanodes[node_id]["url"])
                  for node_id in candidates],
    )


def _read_file_bytes(meta: dict) -> bytes:
    import httpx

    content = bytearray()
    active = set(_active_datanodes())
    for block in sorted(meta["blocks"], key=lambda item: item["seq"]):
        ids = block.get("replicas", [block["datanode_id"]])
        ordered = sorted(ids, key=lambda node_id: node_id not in active)
        result = None
        for node_id in ordered:
            node = datanodes.get(node_id)
            if not node:
                continue
            try:
                response = httpx.get(
                    f"{node.get('internal_url', node['url'])}/block/{block['block_id']}",
                    headers={"X-Block-Token": _block_token(block["block_id"])},
                    timeout=5,
                )
                response.raise_for_status()
                result = response.content
                break
            except httpx.HTTPError:
                continue
        if result is None:
            raise HTTPException(status_code=503, detail=f"No se pudo leer el bloque {block['block_id']}")
        content.extend(result)
    return bytes(content[:meta["size"]])


def _read_file_range(meta: dict, offset: int, length: int) -> bytes:
    import httpx

    start = min(offset, meta["size"])
    end = min(offset + length, meta["size"])
    if start >= end:
        return b""
    first_seq = start // BLOCK_SIZE
    last_seq = (end - 1) // BLOCK_SIZE
    blocks = {block["seq"]: block for block in meta["blocks"]}
    active = set(_active_datanodes())
    result = bytearray()
    for seq in range(first_seq, last_seq + 1):
        block = blocks.get(seq)
        if block is None:
            raise HTTPException(status_code=503, detail=f"Falta el bloque {seq}")
        node_ids = block.get("replicas", [block["datanode_id"]])
        node_ids = sorted(node_ids, key=lambda node_id: node_id not in active)
        chunk = None
        for node_id in node_ids:
            node = datanodes.get(node_id)
            if not node:
                continue
            try:
                response = httpx.get(
                    f"{node.get('internal_url', node['url'])}/block/{block['block_id']}",
                    headers={"X-Block-Token": _block_token(block["block_id"])},
                    timeout=5,
                )
                response.raise_for_status()
                chunk = response.content
                break
            except httpx.HTTPError:
                continue
        if chunk is None:
            raise HTTPException(status_code=503, detail=f"No se pudo leer el bloque {block['block_id']}")
        block_start = seq * BLOCK_SIZE
        slice_start = max(start - block_start, 0)
        slice_end = min(end - block_start, len(chunk))
        result.extend(chunk[slice_start:slice_end])
    return bytes(result)


def _store_file_bytes(content: bytes) -> List[dict]:
    import httpx

    active = sorted(_active_datanodes())
    if not active:
        raise HTTPException(status_code=503, detail="No hay DataNodes activos")
    if len(active) < REPLICATION_FACTOR:
        raise HTTPException(status_code=503, detail="No hay suficientes DataNodes activos para replicar")
    replica_count = REPLICATION_FACTOR
    block_count = max(1, (len(content) + BLOCK_SIZE - 1) // BLOCK_SIZE)
    blocks = []
    for seq in range(block_count):
        block_id = str(uuid.uuid4())
        chunk = content[seq * BLOCK_SIZE:(seq + 1) * BLOCK_SIZE]
        start = next(_rr_counter) % len(active)
        replicas = [active[(start + offset) % len(active)] for offset in range(replica_count)]
        successful = []
        try:
            for node_id in replicas:
                response = httpx.put(
                    f"{datanodes[node_id].get('internal_url', datanodes[node_id]['url'])}/block/{block_id}",
                    content=chunk,
                    headers={"X-Block-Token": _block_token(block_id)},
                    timeout=30,
                )
                response.raise_for_status()
                successful.append(node_id)
        except httpx.HTTPError as exc:
            for node_id in successful:
                try:
                    httpx.delete(
                        f"{datanodes[node_id].get('internal_url', datanodes[node_id]['url'])}/block/{block_id}",
                        headers={"X-Block-Token": _block_token(block_id)},
                        timeout=3,
                    )
                except httpx.HTTPError:
                    pass
            _delete_blocks(blocks)
            raise HTTPException(status_code=503, detail="No se pudo replicar un bloque") from exc
        blocks.append({"block_id": block_id, "seq": seq, "datanode_id": replicas[0], "replicas": replicas})
    return blocks


# ---------------------------------------------------------------------------
# Gestion del sistema de archivos (RF1)
# ---------------------------------------------------------------------------
@app.get("/fs/ls")
def ls(path: str = "/", user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        if path != "/" and path not in directories:
            raise HTTPException(status_code=404, detail="Directorio no existe")
        if path != "/" and directory_owners.get(path) != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para listar este directorio")

        child_dirs = set()
        child_files = []

        for d in directories:
            if d == path:
                continue
            if _parent(d) == path and (directory_owners.get(d) == user or _is_admin(user)):
                child_dirs.add(d.rsplit("/", 1)[-1])

        for f, meta in files.items():
            if meta.get("ready", True) and _parent(f) == path and (meta["owner"] == user or _is_admin(user)):
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
        parent = _parent(path)
        if parent != "/" and directory_owners.get(parent) != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para crear en este directorio")
        directories.add(path)
        directory_owners[path] = user
        _save_state()
    return {"status": "ok", "path": path}


@app.delete("/fs/rmdir")
def rmdir(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        _cleanup_sessions()
        if path == "/":
            raise HTTPException(status_code=400, detail="No se puede borrar la raiz")
        if path not in directories:
            raise HTTPException(status_code=404, detail="Directorio no existe")
        if any(session["path"].startswith(path + "/") for session in open_handles.values()):
            raise HTTPException(status_code=409, detail="El directorio contiene archivos abiertos")
        if directory_owners.get(path) != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para borrar este directorio")
        has_children = any(_parent(d) == path for d in directories) or \
            any(_parent(f) == path for f in files)
        if has_children:
            raise HTTPException(status_code=409, detail="Directorio no esta vacio")
        directories.remove(path)
        directory_owners.pop(path, None)
        _save_state()
    return {"status": "ok"}


@app.delete("/fs/rm")
def rm(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        _cleanup_sessions()
        meta = files.get(path)
        if meta is None:
            raise HTTPException(status_code=404, detail="Archivo no existe")
        if meta["owner"] != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para borrar este archivo")
        if any(session["path"] == path for session in open_handles.values()):
            raise HTTPException(status_code=409, detail="El archivo esta abierto")
        del files[path]
        _save_state()
    # Mejor esfuerzo: pedirle a cada DataNode que borre su bloque.
    import httpx
    for b in meta["blocks"]:
        for node_id in b.get("replicas", [b["datanode_id"]]):
            dn = datanodes.get(node_id)
            if not dn:
                continue
            try:
                httpx.delete(
                    f"{dn.get('internal_url', dn['url'])}/block/{b['block_id']}",
                    headers={"X-Block-Token": _block_token(b["block_id"])},
                    timeout=3,
                )
            except httpx.HTTPError:
                pass
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Transferencia de archivos (RF2) -- planificacion de bloques
# ---------------------------------------------------------------------------
@app.post("/fs/create", response_model=CreateFileResponse)
def create_file(req: CreateFileRequest, user: str = Depends(get_current_user)):
    path = _normalize(req.path)
    with lock:
        if req.size < 0:
            raise HTTPException(status_code=400, detail="El tamaño no puede ser negativo")
        if _parent(path) not in directories:
            raise HTTPException(status_code=404, detail="El directorio padre no existe")
        parent = _parent(path)
        if parent != "/" and directory_owners.get(parent) != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para crear en este directorio")
        if path in files:
            raise HTTPException(status_code=409, detail="El archivo ya existe")
        num_blocks = max(1, -(-req.size // BLOCK_SIZE))  # ceil div
        active = sorted(_active_datanodes())
        if not active:
            raise HTTPException(status_code=503, detail="No hay DataNodes activos registrados")
        if len(active) < REPLICATION_FACTOR:
            raise HTTPException(status_code=503, detail="No hay suficientes DataNodes activos para replicar")
        replica_count = REPLICATION_FACTOR
        blocks = []
        for seq in range(num_blocks):
            start = next(_rr_counter) % len(active)
            replicas = [active[(start + offset) % len(active)] for offset in range(replica_count)]
            block_id = str(uuid.uuid4())
            blocks.append({"block_id": block_id, "seq": seq, "datanode_id": replicas[0], "replicas": replicas})

        files[path] = {"size": req.size, "owner": user, "blocks": blocks, "ready": False}
        _save_state()
        plan = [_block_plan(block, block["seq"]) for block in blocks]
    return CreateFileResponse(path=path, block_size=BLOCK_SIZE, blocks=plan)


@app.get("/fs/locate", response_model=LocateResponse)
def locate(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        _cleanup_sessions()
        meta = files.get(path)
        if meta is None:
            raise HTTPException(status_code=404, detail="Archivo no existe")
        if meta["owner"] != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para acceder a este archivo")
        if file_locks.get(path):
            raise HTTPException(status_code=409, detail="El archivo esta bloqueado para escritura")
        if not meta.get("ready", True):
            raise HTTPException(status_code=409, detail="El archivo todavia no esta completo")
        plan = [
            _block_plan(block, block["seq"])
            for block in sorted(meta["blocks"], key=lambda b: b["seq"])
        ]
    return LocateResponse(path=path, size=meta["size"], blocks=plan)


@app.post("/fs/commit")
def commit_file(req: CommitRequest, user: str = Depends(get_current_user)):
    import httpx

    path = _normalize(req.path)
    with lock:
        meta = files.get(path)
        if meta is None or meta["owner"] != user:
            raise HTTPException(status_code=404, detail="Subida no encontrada")
        if meta.get("ready", True):
            return {"status": "ok", "path": path}
        blocks = [dict(block) for block in meta["blocks"]]
    for block in blocks:
        for node_id in block.get("replicas", [block["datanode_id"]]):
            node = datanodes.get(node_id)
            if not node:
                raise HTTPException(status_code=503, detail="Replica sin registro")
            try:
                response = httpx.get(
                    f"{node.get('internal_url', node['url'])}/block/{block['block_id']}/status",
                    headers={"X-Block-Token": _block_token(block["block_id"])},
                    timeout=5,
                )
                response.raise_for_status()
                status_info = response.json()
            except httpx.HTTPError as exc:
                raise HTTPException(status_code=503, detail="No se pudo verificar una replica") from exc
            expected_size = min(BLOCK_SIZE, max(0, meta["size"] - block["seq"] * BLOCK_SIZE))
            if not status_info["exists"] or status_info["size"] != expected_size:
                raise HTTPException(status_code=503, detail="Falta una replica o su tamano no coincide")
    with lock:
        current = files.get(path)
        if current is None:
            raise HTTPException(status_code=404, detail="Subida no encontrada")
        current["ready"] = True
        _save_state()
    return {
        "status": "ok",
        "path": path,
        "replicas": sum(len(block.get("replicas", [])) for block in blocks),
    }


@app.delete("/fs/abort")
def abort_file(path: str, user: str = Depends(get_current_user)):
    path = _normalize(path)
    with lock:
        meta = files.get(path)
        if meta is None or meta["owner"] != user:
            raise HTTPException(status_code=404, detail="Subida no encontrada")
        if meta.get("ready", True):
            raise HTTPException(status_code=409, detail="No se puede abortar un archivo confirmado")
        del files[path]
        _save_state()
    _delete_blocks(meta["blocks"])
    return {"status": "aborted", "path": path}


@app.post("/fs/open")
def open_file(req: OpenRequest, user: str = Depends(get_current_user)):
    path = _normalize(req.path)
    if req.mode not in {"r", "r+", "w"}:
        raise HTTPException(status_code=400, detail="Modo permitido: r, r+ o w")
    with lock:
        _cleanup_sessions()
        meta = files.get(path)
        if meta is None:
            raise HTTPException(status_code=404, detail="Archivo no existe")
        if meta["owner"] != user and not _is_admin(user):
            raise HTTPException(status_code=403, detail="No tienes permiso para acceder a este archivo")
        if req.mode == "r" and file_locks.get(path):
            raise HTTPException(status_code=409, detail="El archivo esta bloqueado para escritura")
        if req.mode == "w" and any(
            session["path"] == path for session in open_handles.values()
        ):
            raise HTTPException(status_code=409, detail="Hay sesiones activas para este archivo")
        handle = secrets.token_urlsafe(24)
        if req.mode == "w" and path in file_locks:
            raise HTTPException(status_code=409, detail="El archivo ya esta bloqueado")
        open_handles[handle] = {
            "path": path, "user": user, "mode": req.mode, "last_activity": time.time()
        }
        if req.mode == "w":
            file_locks[path] = handle
    if req.mode == "w":
        try:
            new_blocks = _store_file_bytes(b"")
        except Exception:
            with lock:
                open_handles.pop(handle, None)
                file_locks.pop(path, None)
            raise
        with lock:
            old_meta = files[path]
            files[path] = {**old_meta, "size": 0, "blocks": new_blocks}
            _save_state()
        _delete_blocks(old_meta["blocks"])
    return {"handle": handle, "path": path, "mode": req.mode, "size": files[path]["size"]}


@app.post("/fs/lock")
def lock_file(req: HandleRequest, user: str = Depends(get_current_user)):
    with lock:
        _cleanup_sessions()
        session = open_handles.get(req.handle)
        if not session or session["user"] != user:
            raise HTTPException(status_code=404, detail="Handle no encontrado")
        if session["mode"] not in {"r+", "w"}:
            raise HTTPException(status_code=403, detail="Abre el archivo en modo de escritura")
        path = session["path"]
        owner = file_locks.get(path)
        if owner and owner != req.handle:
            raise HTTPException(status_code=409, detail="El archivo ya esta bloqueado")
        if any(
            handle != req.handle and session["path"] == path and session["mode"] == "r"
            for handle, session in open_handles.items()
        ):
            raise HTTPException(status_code=409, detail="Hay lectores activos")
        file_locks[path] = req.handle
        session["last_activity"] = time.time()
    return {"status": "locked", "path": path}


@app.post("/fs/unlock")
def unlock_file(req: HandleRequest, user: str = Depends(get_current_user)):
    with lock:
        _cleanup_sessions()
        session = open_handles.get(req.handle)
        if not session or session["user"] != user:
            raise HTTPException(status_code=404, detail="Handle no encontrado")
        path = session["path"]
        if file_locks.get(path) != req.handle:
            raise HTTPException(status_code=409, detail="El handle no posee el lock")
        del file_locks[path]
        session["last_activity"] = time.time()
    return {"status": "unlocked", "path": path}


@app.post("/fs/read")
def read_file(req: ReadRequest, user: str = Depends(get_current_user)):
    if req.offset < 0 or req.length < 0 or req.length > 16 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Rango de lectura invalido")
    with lock:
        _cleanup_sessions()
        session = open_handles.get(req.handle)
        if not session or session["user"] != user:
            raise HTTPException(status_code=404, detail="Handle no encontrado")
        path = session["path"]
    with _file_io_lock(path):
        with lock:
            session = open_handles.get(req.handle)
            if not session or session["user"] != user:
                raise HTTPException(status_code=404, detail="Handle no encontrado")
            if file_locks.get(path) and file_locks[path] != req.handle:
                raise HTTPException(status_code=409, detail="El archivo esta bloqueado para escritura")
            meta = dict(files[path])
            session["last_activity"] = time.time()
        content = _read_file_range(meta, req.offset, req.length)
    return {"data": base64.b64encode(content).decode("ascii"), "bytes": len(content)}


@app.post("/fs/write")
def write_file(req: WriteRequest, user: str = Depends(get_current_user)):
    if req.offset < 0:
        raise HTTPException(status_code=400, detail="Offset invalido")
    try:
        data = base64.b64decode(req.data, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise HTTPException(status_code=400, detail="Los datos deben estar codificados en Base64") from exc
    with lock:
        _cleanup_sessions()
        session = open_handles.get(req.handle)
        if not session or session["user"] != user:
            raise HTTPException(status_code=404, detail="Handle no encontrado")
        path = session["path"]
    with _file_io_lock(path):
        with lock:
            _cleanup_sessions()
            session = open_handles.get(req.handle)
            if not session or session["user"] != user:
                raise HTTPException(status_code=404, detail="Handle no encontrado")
            path = session["path"]
            if session["mode"] not in {"r+", "w"} or file_locks.get(path) != req.handle:
                raise HTTPException(status_code=409, detail="Se requiere handle de escritura con lock")
            old_meta = dict(files[path])
            session["last_activity"] = time.time()
        old_content = _read_file_bytes(old_meta)
        end = req.offset + len(data)
        new_content = bytearray(max(len(old_content), end))
        new_content[:len(old_content)] = old_content
        new_content[req.offset:end] = data
        new_blocks = _store_file_bytes(bytes(new_content))
        with lock:
            files[path] = {**old_meta, "size": len(new_content), "blocks": new_blocks}
            _save_state()
        _delete_blocks(old_meta["blocks"])
    return {"status": "ok", "bytes_written": len(data), "size": len(new_content)}


@app.post("/fs/close")
def close_file(req: HandleRequest, user: str = Depends(get_current_user)):
    with lock:
        _cleanup_sessions()
        session = open_handles.get(req.handle)
        if not session or session["user"] != user:
            raise HTTPException(status_code=404, detail="Handle no encontrado")
        if file_locks.get(session["path"]) == req.handle:
            del file_locks[session["path"]]
        del open_handles[req.handle]
    return {"status": "closed"}


# ---------------------------------------------------------------------------
# Mantenimiento: re-replicacion y limpieza de bloques huerfanos (Hito 4)
# ---------------------------------------------------------------------------
def _node_url(node_id: str) -> Optional[str]:
    node = datanodes.get(node_id)
    if not node:
        return None
    return node.get("internal_url", node["url"])


def _blocks_per_node() -> Dict[str, int]:
    load = {node_id: 0 for node_id in datanodes}
    for meta in files.values():
        for block in meta["blocks"]:
            for node_id in block.get("replicas", [block["datanode_id"]]):
                load[node_id] = load.get(node_id, 0) + 1
    return load


def _repair_blocks() -> int:
    """Busca bloques con menos replicas vivas que REPLICATION_FACTOR y los copia
    desde una replica sana hacia otro DataNode activo."""
    import httpx

    with lock:
        active = set(_active_datanodes())
        load = _blocks_per_node()
        pending = []
        lost = 0
        for path, meta in files.items():
            if not meta.get("ready", True):
                continue
            for block in meta["blocks"]:
                replicas = block.get("replicas", [block["datanode_id"]])
                alive = [node_id for node_id in replicas if node_id in active]
                if not alive:
                    lost += 1
                elif len(alive) < REPLICATION_FACTOR:
                    pending.append((path, block["block_id"], list(replicas), alive))
        repair_stats["lost_blocks"] = lost

    repaired = 0
    for path, block_id, replicas, alive in pending:
        faltan = REPLICATION_FACTOR - len(alive)
        # preferimos los nodos con menos bloques para no desbalancear
        destinos = sorted(active - set(replicas), key=lambda node_id: (load.get(node_id, 0), node_id))[:faltan]
        if not destinos:
            continue
        token = _block_token(block_id)
        data = None
        for node_id in alive:
            try:
                response = httpx.get(f"{_node_url(node_id)}/block/{block_id}",
                                     headers={"X-Block-Token": token}, timeout=10)
                response.raise_for_status()
                data = response.content
                break
            except httpx.HTTPError:
                continue
        if data is None:
            continue

        copiados = []
        for node_id in destinos:
            try:
                response = httpx.put(f"{_node_url(node_id)}/block/{block_id}", content=data,
                                     headers={"X-Block-Token": token}, timeout=30)
                response.raise_for_status()
                copiados.append(node_id)
                load[node_id] = load.get(node_id, 0) + 1
            except httpx.HTTPError:
                continue
        if not copiados:
            continue

        with lock:
            # el archivo pudo cambiar mientras copiabamos; solo actualizamos si el bloque sigue ahi
            meta = files.get(path)
            block = None
            if meta:
                block = next((b for b in meta["blocks"] if b["block_id"] == block_id), None)
            if block is not None:
                block["replicas"] = alive + copiados
                block["datanode_id"] = block["replicas"][0]
                _save_state()
                repaired += 1
                print(f"[repair] bloque {block_id} de {path}: {alive} + {copiados}")
        if block is None:
            for node_id in copiados:
                try:
                    httpx.delete(f"{_node_url(node_id)}/block/{block_id}",
                                 headers={"X-Block-Token": token}, timeout=3)
                except httpx.HTTPError:
                    pass
    return repaired


def _collect_orphans() -> int:
    """Borra de los DataNodes los bloques que ya no aparecen en la metadata
    (por ejemplo, copias viejas de un nodo que estuvo caido y volvio)."""
    import httpx

    with lock:
        active = list(_active_datanodes())
    deleted = 0
    for node_id in active:
        url = _node_url(node_id)
        try:
            response = httpx.get(f"{url}/blocks", headers={"X-Internal-Secret": INTERNAL_SECRET}, timeout=5)
            response.raise_for_status()
            stored = response.json()["blocks"]
        except (httpx.HTTPError, KeyError, ValueError):
            continue
        # la metadata se mira DESPUES de listar el disco: asi un bloque recien
        # creado ya aparece referenciado y no se borra por error
        with lock:
            referenced = {
                block["block_id"]: set(block.get("replicas", [block["datanode_id"]]))
                for meta in files.values() for block in meta["blocks"]
            }
        for item in stored:
            block_id = item["block_id"]
            if item.get("age", 0) < ORPHAN_GRACE:
                continue
            if node_id in referenced.get(block_id, set()):
                continue
            try:
                httpx.delete(f"{url}/block/{block_id}",
                             headers={"X-Block-Token": _block_token(block_id)}, timeout=3)
                deleted += 1
            except httpx.HTTPError:
                pass
    return deleted


def _repair_loop(stop: threading.Event) -> None:
    while not stop.wait(REPAIR_INTERVAL):
        try:
            repair_stats["blocks_repaired"] += _repair_blocks()
            repair_stats["orphans_deleted"] += _collect_orphans()
            repair_stats["runs"] += 1
            repair_stats["last_run"] = time.time()
        except Exception as exc:  # el hilo no se puede morir por un error puntual
            print(f"[repair] error: {exc}")


@app.get("/admin/cluster")
def cluster_status(user: str = Depends(get_current_user)):
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Solo admin puede ver el estado del cluster")
    with lock:
        active = set(_active_datanodes())
        load = _blocks_per_node()
        sub_replicados = 0
        total_bloques = 0
        for meta in files.values():
            for block in meta["blocks"]:
                total_bloques += 1
                vivos = [n for n in block.get("replicas", [block["datanode_id"]]) if n in active]
                if len(vivos) < REPLICATION_FACTOR:
                    sub_replicados += 1
        return {
            "replication_factor": REPLICATION_FACTOR,
            "block_size": BLOCK_SIZE,
            "files": len(files),
            "blocks": total_bloques,
            "under_replicated": sub_replicados,
            "datanodes": [
                {
                    "datanode_id": node_id,
                    "url": info["url"],
                    "active": node_id in active,
                    "seconds_since_heartbeat": round(time.time() - info["last_heartbeat"], 1),
                    "blocks": load.get(node_id, 0),
                }
                for node_id, info in sorted(datanodes.items())
            ],
            "maintenance": dict(repair_stats),
        }


# ---------------------------------------------------------------------------
# Registro y heartbeat de DataNodes
# ---------------------------------------------------------------------------
@app.post("/datanode/register")
def register_datanode(req: RegisterRequest, secret: Optional[str] = Header(default=None, alias="X-Internal-Secret")):
    if not secret or not hmac.compare_digest(secret, INTERNAL_SECRET):
        raise HTTPException(status_code=401, detail="Credencial interna invalida")
    with lock:
        datanodes[req.datanode_id] = {
            "url": req.url,
            "internal_url": req.internal_url or req.url,
            "last_heartbeat": time.time(),
        }
    return {"status": "ok"}


@app.post("/datanode/heartbeat")
def heartbeat(req: HeartbeatRequest, secret: Optional[str] = Header(default=None, alias="X-Internal-Secret")):
    if not secret or not hmac.compare_digest(secret, INTERNAL_SECRET):
        raise HTTPException(status_code=401, detail="Credencial interna invalida")
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