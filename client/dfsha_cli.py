#!/usr/bin/env python3
"""CLI DFSha para gestionar paths, transferir archivos y usar acceso por bloques."""
import argparse
import base64
import os
import posixpath
import shlex
import sys

import httpx

CONTROL_URL = os.environ.get("DFSHA_CONTROL_URL", "http://localhost:8000")
USER = os.environ.get("DFSHA_USER")
PASSWORD = os.environ.get("DFSHA_PASSWORD")
TOTP_CODE = os.environ.get("DFSHA_TOTP_CODE")
API_KEY = os.environ.get("DFSHA_API_KEY")


def _auth():
    if not USER or not PASSWORD:
        sys.exit("Error: define DFSHA_USER y DFSHA_PASSWORD (variables de entorno)")
    return (USER, PASSWORD)


def _auth_kwargs():
    headers = {}
    if TOTP_CODE:
        headers["X-TOTP-Code"] = TOTP_CODE
    if API_KEY:
        headers["X-API-Key"] = API_KEY
        return {"headers": headers}
    return {"auth": _auth(), "headers": headers}


def _check(resp: httpx.Response):
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        sys.exit(f"Error {resp.status_code}: {detail}")
    return resp


def cmd_login(args):
    r = httpx.post(f"{CONTROL_URL}/auth/login", **_auth_kwargs())
    _check(r)
    print("Login OK:", r.json())


def cmd_ls(args):
    r = httpx.get(f"{CONTROL_URL}/fs/ls", params={"path": args.path}, **_auth_kwargs())
    _check(r)
    data = r.json()
    for d in data["directories"]:
        print(f"  <dir>  {d}/")
    for f in data["files"]:
        print(f"  <file> {f['name']}  ({f['size']} bytes)")


def cmd_mkdir(args):
    r = httpx.post(f"{CONTROL_URL}/fs/mkdir", json={"path": args.path}, **_auth_kwargs())
    _check(r)
    print("mkdir OK:", args.path)


def cmd_rmdir(args):
    r = httpx.delete(f"{CONTROL_URL}/fs/rmdir", params={"path": args.path}, **_auth_kwargs())
    _check(r)
    print("rmdir OK:", args.path)


def cmd_rm(args):
    r = httpx.delete(f"{CONTROL_URL}/fs/rm", params={"path": args.path}, **_auth_kwargs())
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
        **_auth_kwargs(),
    )
    _check(r)
    plan = r.json()
    block_size = plan["block_size"]

    try:
        with open(local_path, "rb") as f:
            for block in plan["blocks"]:
                chunk = f.read(block_size)
                uploaded = []
                for replica in block["replicas"]:
                    resp = httpx.put(
                        f"{replica['datanode_url']}/block/{block['block_id']}",
                        content=chunk,
                        headers={"X-Block-Token": block["block_token"]},
                        timeout=30,
                    )
                    _check(resp)
                    uploaded.append(replica["datanode_id"])
                print(f"  bloque {block['seq']} -> {', '.join(uploaded)} "
                      f"({len(chunk)} bytes por replica) OK")

        committed = httpx.post(
            f"{CONTROL_URL}/fs/commit",
            json={"path": remote_path},
            **_auth_kwargs(),
        )
        _check(committed)
    except (httpx.HTTPError, SystemExit):
        httpx.delete(
            f"{CONTROL_URL}/fs/abort",
            params={"path": remote_path},
            **_auth_kwargs(),
        )
        raise

    print(f"put OK: {local_path} -> {remote_path} "
          f"({len(plan['blocks'])} bloque(s), {size} bytes)")


def cmd_get(args):
    remote_path, local_path = args.remote, args.local
    opened = httpx.post(
        f"{CONTROL_URL}/fs/open",
        json={"path": remote_path, "mode": "r"},
        **_auth_kwargs(),
    )
    _check(opened)
    handle = opened.json()["handle"]
    try:
        r = httpx.get(f"{CONTROL_URL}/fs/locate", params={"path": remote_path}, **_auth_kwargs())
        _check(r)
        info = r.json()

        with open(local_path, "wb") as out:
            for block in sorted(info["blocks"], key=lambda b: b["seq"]):
                last_error = None
                for replica in block["replicas"]:
                    try:
                        resp = httpx.get(
                            f"{replica['datanode_url']}/block/{block['block_id']}",
                            headers={"X-Block-Token": block["block_token"]},
                            timeout=30,
                        )
                        _check(resp)
                        break
                    except (httpx.HTTPError, SystemExit) as exc:
                        last_error = exc
                else:
                    raise SystemExit(f"No se pudo recuperar el bloque {block['block_id']}: {last_error}")
                out.write(resp.content)
                print(f"  bloque {block['seq']} <- {replica['datanode_id']} "
                      f"({len(resp.content)} bytes) OK")

        print(f"get OK: {remote_path} -> {local_path} ({info['size']} bytes)")
    finally:
        httpx.post(
            f"{CONTROL_URL}/fs/close",
            json={"handle": handle},
            **_auth_kwargs(),
        )


def cmd_open(args):
    r = httpx.post(f"{CONTROL_URL}/fs/open", json={"path": args.path, "mode": args.mode}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_read(args):
    r = httpx.post(f"{CONTROL_URL}/fs/read", json={"handle": args.handle, "offset": args.offset, "length": args.length}, **_auth_kwargs())
    _check(r)
    data = base64.b64decode(r.json()["data"])
    with open(args.local, "wb") as output:
        output.write(data)
    print(f"read OK: {len(data)} bytes -> {args.local}")


def cmd_write(args):
    with open(args.local, "rb") as source:
        data = base64.b64encode(source.read()).decode("ascii")
    r = httpx.post(f"{CONTROL_URL}/fs/write", json={"handle": args.handle, "offset": args.offset, "data": data}, **_auth_kwargs())
    _check(r)
    print("write OK:", r.json())


def cmd_lock(args):
    r = httpx.post(f"{CONTROL_URL}/fs/lock", json={"handle": args.handle}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_unlock(args):
    r = httpx.post(f"{CONTROL_URL}/fs/unlock", json={"handle": args.handle}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_close(args):
    r = httpx.post(f"{CONTROL_URL}/fs/close", json={"handle": args.handle}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_totp_setup(args):
    r = httpx.post(f"{CONTROL_URL}/auth/totp/setup", **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_totp_confirm(args):
    r = httpx.post(f"{CONTROL_URL}/auth/totp/confirm", json={"code": args.code}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_totp_disable(args):
    r = httpx.delete(f"{CONTROL_URL}/auth/totp", **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_api_key_create(args):
    r = httpx.post(f"{CONTROL_URL}/auth/api-keys", json={"name": args.name}, **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_api_key_delete(args):
    r = httpx.delete(f"{CONTROL_URL}/auth/api-keys/{args.key_id}", **_auth_kwargs())
    _check(r)
    print(r.json())


def cmd_shell(args):
    cwd = "/"
    print("DFSha shell. Usa 'exit' para salir.")
    while True:
        try:
            line = input(f"dfsha:{cwd}$ ").strip()
        except EOFError:
            break
        if not line:
            continue
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f"Error: {exc}")
            continue
        command, *values = parts
        if command in {"exit", "quit"}:
            break
        if command == "cd":
            target = values[0] if values else "/"
            path = _remote_path(target, cwd)
            try:
                response = httpx.get(
                    f"{CONTROL_URL}/fs/ls", params={"path": path}, **_auth_kwargs()
                )
                _check(response)
                cwd = path
                print(cwd)
            except (SystemExit, httpx.HTTPError) as exc:
                print(exc)
            continue
        if command == "ls":
            target = _remote_path(values[0], cwd) if values else cwd
            handler, namespace = cmd_ls, argparse.Namespace(path=target)
        elif command in {"mkdir", "rmdir", "rm"} and len(values) == 1:
            handler = {"mkdir": cmd_mkdir, "rmdir": cmd_rmdir, "rm": cmd_rm}[command]
            namespace = argparse.Namespace(path=_remote_path(values[0], cwd))
        elif command == "put" and len(values) == 2:
            handler = cmd_put
            namespace = argparse.Namespace(local=values[0], remote=_remote_path(values[1], cwd))
        elif command == "get" and len(values) == 2:
            handler = cmd_get
            namespace = argparse.Namespace(remote=_remote_path(values[0], cwd), local=values[1])
        elif command == "login" and not values:
            handler, namespace = cmd_login, argparse.Namespace()
        else:
            print("Comando o argumentos invalidos")
            continue
        try:
            handler(namespace)
        except (SystemExit, httpx.HTTPError) as exc:
            print(exc)


def _remote_path(path: str, cwd: str) -> str:
    normalized = posixpath.normpath(path if path.startswith("/") else posixpath.join(cwd, path))
    return normalized if normalized.startswith("/") else "/" + normalized


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

    p = sub.add_parser("open")
    p.add_argument("path")
    p.add_argument("--mode", choices=("r", "r+", "w"), default="r")
    p.set_defaults(func=cmd_open)

    p = sub.add_parser("read")
    p.add_argument("handle")
    p.add_argument("offset", type=int)
    p.add_argument("length", type=int)
    p.add_argument("local")
    p.set_defaults(func=cmd_read)

    p = sub.add_parser("write")
    p.add_argument("handle")
    p.add_argument("offset", type=int)
    p.add_argument("local")
    p.set_defaults(func=cmd_write)

    for command, func in (("lock", cmd_lock), ("unlock", cmd_unlock), ("close", cmd_close)):
        p = sub.add_parser(command)
        p.add_argument("handle")
        p.set_defaults(func=func)

    sub.add_parser("totp-setup").set_defaults(func=cmd_totp_setup)
    p = sub.add_parser("totp-confirm")
    p.add_argument("code")
    p.set_defaults(func=cmd_totp_confirm)
    sub.add_parser("totp-disable").set_defaults(func=cmd_totp_disable)

    p = sub.add_parser("api-key-create")
    p.add_argument("--name", default="cli")
    p.set_defaults(func=cmd_api_key_create)
    p = sub.add_parser("api-key-delete")
    p.add_argument("key_id")
    p.set_defaults(func=cmd_api_key_delete)

    sub.add_parser("shell").set_defaults(func=cmd_shell)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()