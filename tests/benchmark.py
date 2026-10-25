"""Mediciones de rendimiento para el informe.

Uso:
    python tests/benchmark.py            # levanta un cluster local temporal
    python tests/benchmark.py --remote   # usa DFSHA_CONTROL_URL / DFSHA_USER / DFSHA_PASSWORD

Mide:
  1. tiempo y throughput de put/get para varios tamanos
  2. subidas concurrentes (varios clientes a la vez)
  3. cuanto tarda el cluster en volver a factor de replicacion 2 al caer un nodo
"""
import argparse
import json
import os
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import Cluster, run_cli  # noqa: E402

MB = 1024 * 1024


def medir_transferencias(env, carpeta, tamanos):
    filas = []
    run_cli(env, "mkdir", "/bench", check=False)
    for mb in tamanos:
        local = carpeta / f"f{mb}.bin"
        local.write_bytes(os.urandom(mb * MB))
        t0 = time.perf_counter()
        run_cli(env, "put", str(local), f"/bench/f{mb}.bin")
        t_put = time.perf_counter() - t0
        t0 = time.perf_counter()
        run_cli(env, "get", f"/bench/f{mb}.bin", str(carpeta / f"g{mb}.bin"))
        t_get = time.perf_counter() - t0
        ok = (carpeta / f"g{mb}.bin").read_bytes() == local.read_bytes()
        filas.append({
            "mb": mb, "bloques": -(-mb * MB // (4 * MB)),
            "put_s": round(t_put, 2), "get_s": round(t_get, 2),
            "put_mb_s": round(mb / t_put, 1), "get_mb_s": round(mb / t_get, 1),
            "integro": ok,
        })
        print(filas[-1])
    return filas


def medir_concurrencia(env, carpeta, clientes, mb):
    local = carpeta / "conc.bin"
    local.write_bytes(os.urandom(mb * MB))

    def subir(i):
        run_cli(env, "put", str(local), f"/bench/conc_{clientes}_{i}.bin")

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=clientes) as pool:
        list(pool.map(subir, range(clientes)))
    total = time.perf_counter() - t0
    fila = {"clientes": clientes, "mb_por_cliente": mb, "total_s": round(total, 2),
            "mb_s_agregado": round(clientes * mb / total, 1)}
    print(fila)
    return fila


def medir_recuperacion(cluster):
    cluster.stop("dn1")
    t0 = time.perf_counter()
    while True:
        r = httpx.get(f"{cluster.control_url}/admin/cluster", auth=("admin", "admin123")).json()
        caido = not next(n for n in r["datanodes"] if n["datanode_id"] == "dn1")["active"]
        if caido and r["under_replicated"] == 0:
            break
        time.sleep(0.5)
    total = time.perf_counter() - t0
    fila = {"recuperacion_s": round(total, 1), "bloques_reparados": r["maintenance"]["blocks_repaired"]}
    print(fila)
    return fila


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--sizes", default="1,10,50,100")
    parser.add_argument("--out", default="bench_results.json")
    args = parser.parse_args()

    tamanos = [int(x) for x in args.sizes.split(",")]
    carpeta = Path(tempfile.mkdtemp(prefix="dfsha-bench-"))
    cluster = None
    if args.remote:
        env = dict(os.environ)
    else:
        cluster = Cluster()
        cluster.start_control()
        time.sleep(1.5)
        for n in (1, 2, 3):
            cluster.start_datanode(n)
        cluster.wait_active(3)
        env = dict(cluster.env_base, DFSHA_CONTROL_URL=cluster.control_url,
                   DFSHA_USER="vale", DFSHA_PASSWORD="vale123")
    try:
        resultados = {
            "transferencias": medir_transferencias(env, carpeta, tamanos),
            "concurrencia": [medir_concurrencia(env, carpeta, c, 8) for c in (1, 4, 8)],
        }
        if cluster:
            resultados["recuperacion"] = medir_recuperacion(cluster)
        Path(args.out).write_text(json.dumps(resultados, indent=2))
        print(f"Resultados guardados en {args.out}")
    finally:
        if cluster:
            cluster.shutdown()


if __name__ == "__main__":
    main()
