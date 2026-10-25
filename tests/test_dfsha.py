"""Pruebas de integracion de DFSha (Hito 4).

El orden importa: las ultimas pruebas tumban un DataNode y miran que el
sistema siga respondiendo y se recupere solo.
"""
import base64
import os
import time

import httpx
import pyotp

from conftest import run_cli

VALE = ("vale", "vale123")
ADMIN = ("admin", "admin123")
MB = 1024 * 1024


def _locate(cluster, path, auth=VALE):
    r = httpx.get(f"{cluster.control_url}/fs/locate", params={"path": path}, auth=auth)
    r.raise_for_status()
    return r.json()


def _status(cluster):
    r = httpx.get(f"{cluster.control_url}/admin/cluster", auth=ADMIN)
    r.raise_for_status()
    return r.json()


# --------------------------------------------------------------------------
# RF1 / RF2: gestion de archivos y transferencia
# --------------------------------------------------------------------------
def test_put_get_archivo_grande(cluster, cli_env, tmp_path):
    original = tmp_path / "grande.bin"
    original.write_bytes(os.urandom(10 * MB + 123))
    run_cli(cli_env, "mkdir", "/pruebas")
    out = run_cli(cli_env, "put", str(original), "/pruebas/grande.bin").stdout
    assert "3 bloque(s)" in out

    copia = tmp_path / "copia.bin"
    run_cli(cli_env, "get", "/pruebas/grande.bin", str(copia))
    assert copia.read_bytes() == original.read_bytes()

    listado = run_cli(cli_env, "ls", "/pruebas").stdout
    assert "grande.bin" in listado


def test_bloques_repartidos_y_replicados(cluster):
    info = _locate(cluster, "/pruebas/grande.bin")
    usados = set()
    for block in info["blocks"]:
        replicas = [r["datanode_id"] for r in block["replicas"]]
        assert len(replicas) == 2 and len(set(replicas)) == 2
        usados.update(replicas)
    # con 3 bloques y round-robin deben participar los 3 nodos
    assert usados == {"dn1", "dn2", "dn3"}


def test_mkdir_rmdir_rm(cluster, cli_env, tmp_path):
    archivo = tmp_path / "a.txt"
    archivo.write_text("hola dfsha")
    run_cli(cli_env, "mkdir", "/tmpdir")
    run_cli(cli_env, "put", str(archivo), "/tmpdir/a.txt")
    no_vacio = run_cli(cli_env, "rmdir", "/tmpdir", check=False)
    assert no_vacio.returncode != 0 and "no esta vacio" in no_vacio.stdout + no_vacio.stderr
    run_cli(cli_env, "rm", "/tmpdir/a.txt")
    run_cli(cli_env, "rmdir", "/tmpdir")
    assert "tmpdir" not in run_cli(cli_env, "ls", "/").stdout


# --------------------------------------------------------------------------
# RNF6: seguridad
# --------------------------------------------------------------------------
def test_bloques_cifrados_en_disco(cluster, cli_env, tmp_path):
    texto = b"DATO-SECRETO-QUE-NO-DEBE-VERSE " * 100
    archivo = tmp_path / "secreto.txt"
    archivo.write_bytes(texto)
    run_cli(cli_env, "put", str(archivo), "/pruebas/secreto.txt")
    block = _locate(cluster, "/pruebas/secreto.txt")["blocks"][0]
    for replica in block["replicas"]:
        n = int(replica["datanode_id"][2:])
        crudo = (cluster.block_dir(n) / block["block_id"]).read_bytes()
        assert crudo.startswith(b"DFSB1")
        assert b"DATO-SECRETO" not in crudo


def test_sin_credenciales_y_password_malo(cluster):
    assert httpx.get(f"{cluster.control_url}/fs/ls").status_code == 401
    assert httpx.get(f"{cluster.control_url}/fs/ls", auth=("vale", "otra")).status_code == 401


def test_control_de_acceso_entre_usuarios(cluster):
    r = httpx.post(f"{cluster.control_url}/auth/users", auth=ADMIN,
                   json={"username": "andres", "password": "andres1234"})
    assert r.status_code == 200
    ajeno = httpx.get(f"{cluster.control_url}/fs/locate", params={"path": "/pruebas/grande.bin"},
                      auth=("andres", "andres1234"))
    assert ajeno.status_code == 403
    # andres tampoco ve el directorio de vale
    assert httpx.get(f"{cluster.control_url}/fs/ls", params={"path": "/pruebas"},
                     auth=("andres", "andres1234")).status_code == 403
    # y un usuario normal no puede crear usuarios
    r = httpx.post(f"{cluster.control_url}/auth/users", auth=VALE,
                   json={"username": "x", "password": "12345678"})
    assert r.status_code == 403


def test_datanode_rechaza_token_invalido(cluster):
    block = _locate(cluster, "/pruebas/grande.bin")["blocks"][0]
    url = block["replicas"][0]["datanode_url"]
    r = httpx.get(f"{url}/block/{block['block_id']}", headers={"X-Block-Token": "falso"})
    assert r.status_code == 401
    r = httpx.post(f"{cluster.control_url}/datanode/register",
                   json={"datanode_id": "intruso", "url": "http://evil"})
    assert r.status_code == 401


def test_api_key_y_2fa(cluster):
    r = httpx.post(f"{cluster.control_url}/auth/users", auth=ADMIN,
                   json={"username": "dosfa", "password": "dosfa1234"})
    assert r.status_code == 200
    user = ("dosfa", "dosfa1234")
    secret = httpx.post(f"{cluster.control_url}/auth/totp/setup", auth=user).json()["secret"]
    code = pyotp.TOTP(secret).now()
    assert httpx.post(f"{cluster.control_url}/auth/totp/confirm", auth=user,
                      json={"code": code}).status_code == 200
    # sin codigo ya no entra
    assert httpx.post(f"{cluster.control_url}/auth/login", auth=user).status_code == 401
    ok = httpx.post(f"{cluster.control_url}/auth/login", auth=user,
                    headers={"X-TOTP-Code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200

    key = httpx.post(f"{cluster.control_url}/auth/api-keys", auth=VALE, json={"name": "test"}).json()
    r = httpx.get(f"{cluster.control_url}/fs/ls", headers={"X-API-Key": key["api_key"]})
    assert r.status_code == 200


# --------------------------------------------------------------------------
# RF3 / RNF3: acceso con open/read/write/lock y consistencia
# --------------------------------------------------------------------------
def test_open_write_read_con_lock(cluster, cli_env, tmp_path):
    archivo = tmp_path / "notas.txt"
    archivo.write_bytes(b"0123456789")
    run_cli(cli_env, "put", str(archivo), "/pruebas/notas.txt")
    base = cluster.control_url

    escritor = httpx.post(f"{base}/fs/open", auth=VALE, json={"path": "/pruebas/notas.txt", "mode": "r+"}).json()
    assert httpx.post(f"{base}/fs/lock", auth=VALE, json={"handle": escritor["handle"]}).status_code == 200

    # mientras hay lock, nadie mas puede abrir para leer
    assert httpx.post(f"{base}/fs/open", auth=VALE,
                      json={"path": "/pruebas/notas.txt", "mode": "r"}).status_code == 409

    datos = base64.b64encode(b"ABC").decode()
    r = httpx.post(f"{base}/fs/write", auth=VALE, json={"handle": escritor["handle"], "offset": 3, "data": datos})
    assert r.status_code == 200 and r.json()["size"] == 10
    httpx.post(f"{base}/fs/close", auth=VALE, json={"handle": escritor["handle"]})

    lector = httpx.post(f"{base}/fs/open", auth=VALE, json={"path": "/pruebas/notas.txt", "mode": "r"}).json()
    leido = httpx.post(f"{base}/fs/read", auth=VALE, json={"handle": lector["handle"], "offset": 0, "length": 100}).json()
    assert base64.b64decode(leido["data"]) == b"012ABC6789"
    httpx.post(f"{base}/fs/close", auth=VALE, json={"handle": lector["handle"]})


def test_subida_duplicada_rechazada(cluster, cli_env, tmp_path):
    archivo = tmp_path / "dup.txt"
    archivo.write_text("x")
    run_cli(cli_env, "put", str(archivo), "/pruebas/dup.txt")
    otra = run_cli(cli_env, "put", str(archivo), "/pruebas/dup.txt", check=False)
    assert otra.returncode != 0 and "ya existe" in otra.stdout + otra.stderr


# --------------------------------------------------------------------------
# RNF2: alta disponibilidad (estas van al final porque tumban nodos)
# --------------------------------------------------------------------------
def test_lectura_con_un_datanode_caido(cluster, cli_env, tmp_path):
    original = tmp_path / "ha.bin"
    original.write_bytes(os.urandom(9 * MB))
    run_cli(cli_env, "put", str(original), "/pruebas/ha.bin")

    cluster.stop("dn1")
    copia = tmp_path / "ha_copia.bin"
    run_cli(cli_env, "get", "/pruebas/ha.bin", str(copia))
    assert copia.read_bytes() == original.read_bytes()


def test_re_replicacion_automatica(cluster):
    cluster.wait_active(2)
    deadline = time.time() + 30
    estado = _status(cluster)
    while time.time() < deadline and estado["under_replicated"] > 0:
        time.sleep(1)
        estado = _status(cluster)
    assert estado["under_replicated"] == 0
    assert estado["maintenance"]["blocks_repaired"] > 0
    # todo bloque vuelve a tener 2 replicas, ahora en dn2 y dn3
    for block in _locate(cluster, "/pruebas/grande.bin")["blocks"]:
        assert {r["datanode_id"] for r in block["replicas"]} == {"dn2", "dn3"}


def test_escritura_sigue_funcionando_tras_la_falla(cluster, cli_env, tmp_path):
    archivo = tmp_path / "despues.txt"
    archivo.write_text("subido con un nodo caido")
    run_cli(cli_env, "put", str(archivo), "/pruebas/despues.txt")
    copia = tmp_path / "despues_copia.txt"
    run_cli(cli_env, "get", "/pruebas/despues.txt", str(copia))
    assert copia.read_text() == "subido con un nodo caido"


def test_nodo_que_vuelve_limpia_bloques_viejos(cluster):
    viejos = set(os.listdir(cluster.block_dir(1)))
    assert viejos, "dn1 deberia tener bloques de antes de caerse"
    cluster.start_datanode(1)
    cluster.wait_active(3)
    deadline = time.time() + 30
    while time.time() < deadline:
        restantes = viejos & set(os.listdir(cluster.block_dir(1)))
        if not restantes:
            break
        time.sleep(1)
    assert not restantes
    assert _status(cluster)["maintenance"]["orphans_deleted"] >= len(viejos)


def test_estado_persistente_tras_reiniciar_control(cluster, cli_env, tmp_path):
    cluster.stop("control")
    cluster.start_control()
    cluster.wait_active(3)
    copia = tmp_path / "persist.bin"
    run_cli(cli_env, "get", "/pruebas/grande.bin", str(copia))
    assert copia.stat().st_size == 10 * MB + 123
