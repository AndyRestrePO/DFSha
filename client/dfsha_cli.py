#!/usr/bin/env python3
"""
Cliente DFSha (CLI) -- Hito 2

Uso:
    export DFSHA_USER=vale
    export DFSHA_PASSWORD=vale123
    export DFSHA_CONTROL_URL=http://localhost:8000   # default

    python3 dfsha_cli.py ls /
    python3 dfsha_cli.py mkdir /fotos
    python3 dfsha_cli.py rmdir /fotos
    python3 dfsha_cli.py put ./local.jpg /fotos/local.jpg
    python3 dfsha_cli.py get /fotos/local.jpg ./descargado.jpg
    python3 dfsha_cli.py rm /fotos/local.jpg

RF cubiertos: RF1 (ls/mkdir/rmdir/rm), RF2 (put/get). El subconjunto de
RF3 (open/read/write/close, lock) se deja para cuando se implemente acceso
de bajo nivel / concurrencia en el Hito 3.
"""
import argparse
import os
import sys

import httpx

CONTROL_URL = os.environ.get("DFSHA_CONTROL_URL", "http://localhost:8000")
USER = os.environ.get("DFSHA_USER")
PASSWORD = os.environ.get("DFSHA_PASSWORD")


def _auth():
    if not USER or not PASSWORD:
        sys.exit("Error: define DFSHA_USER y DFSHA_PASSWORD (variables de entorno)")
    return (USER, PASSWORD)


def _check(resp: httpx.Response):
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        sys.exit(f"Error {resp.status_code}: {detail}")
    return resp


def cmd_login(args):
    r = httpx.post(f"{CONTROL_URL}/auth/login", auth=_auth())
    _check(r)
    print("Login OK:", r.json())


def cmd_ls(args):
    r = httpx.get(f"{CONTROL_URL}/fs/ls", params={"path": args.path}, auth=_auth())
    _check(r)
    data = r.json()
    for d in data["directories"]:
        print(f"  <dir>  {d}/")
    for f in data["files"]:
        print(f"  <file> {f['name']}  ({f['size']} bytes)")


def cmd_mkdir(args):
    r = httpx.post(f"{CONTROL_URL}/fs/mkdir", json={"path": args.path}, auth=_auth())
    _check(r)
    print("mkdir OK:", args.path)


def cmd_rmdir(args):
    r = httpx.delete(f"{CONTROL_URL}/fs/rmdir", params={"path": args.path}, auth=_auth())
    _check(r)
    print("rmdir OK:", args.path)


def cmd_rm(args):
    r = httpx.delete(f"{CONTROL_URL}/fs/rm", params={"path": args.path}, auth=_auth())
    _check(r)
    print("rm OK:", args.path)


def cmd_put(args):
    local_path, remote_path = args.local, args.remote
    if not os.path.exists(local_path):
        sys.exit(f"No existe el archivo local: {local_path}")
    size = os.path.getsize(local_path)

    r = httpx.post(
        f"{CONTROL_URL}/fs/create",
        json={"path": remote_path, "size": size},
        auth=_auth(),
    )
    _check(r)
    plan = r.json()
    block_size = plan["block_size"]

    with open(local_path, "rb") as f:
        for block in plan["blocks"]:
            chunk = f.read(block_size)
            resp = httpx.put(
                f"{block['datanode_url']}/block/{block['block_id']}",
                content=chunk,
                timeout=30,
            )
            _check(resp)
            print(f"  bloque {block['seq']} -> {block['datanode_id']} "
                  f"({len(chunk)} bytes) OK")

    print(f"put OK: {local_path} -> {remote_path} "
          f"({len(plan['blocks'])} bloque(s), {size} bytes)")


def cmd_get(args):
    remote_path, local_path = args.remote, args.local
    r = httpx.get(f"{CONTROL_URL}/fs/locate", params={"path": remote_path}, auth=_auth())
    _check(r)
    info = r.json()

    with open(local_path, "wb") as out:
        for block in sorted(info["blocks"], key=lambda b: b["seq"]):
            resp = httpx.get(f"{block['datanode_url']}/block/{block['block_id']}", timeout=30)
            _check(resp)
            out.write(resp.content)
            print(f"  bloque {block['seq']} <- {block['datanode_id']} "
                  f"({len(resp.content)} bytes) OK")

    print(f"get OK: {remote_path} -> {local_path} ({info['size']} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Cliente DFSha")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("login").set_defaults(func=cmd_login)

    p = sub.add_parser("ls")
    p.add_argument("path", nargs="?", default="/")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("mkdir")
    p.add_argument("path")
    p.set_defaults(func=cmd_mkdir)

    p = sub.add_parser("rmdir")
    p.add_argument("path")
    p.set_defaults(func=cmd_rmdir)

    p = sub.add_parser("rm")
    p.add_argument("path")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("put")
    p.add_argument("local")
    p.add_argument("remote")
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("get")
    p.add_argument("remote")
    p.add_argument("local")
    p.set_defaults(func=cmd_get)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()