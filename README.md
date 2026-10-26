# DFSha — Sistema de archivos distribuido con alta disponibilidad

Proyecto 1 de **ST0263 Tópicos Especiales en Telemática / SI3007 Sistemas Distribuidos (2026-2)**, Universidad EAFIT.

DFSha es un sistema de archivos distribuido **por bloques**, inspirado en HDFS/GFS, con arquitectura **Cliente/Servidor (Opción 1)**. Un cliente puede subir y bajar archivos grandes; cada archivo se parte en bloques de 4 MB que se reparten entre varios DataNodes y cada bloque se guarda en 2 nodos distintos.

**Integrantes:** Andrés Restrepo Giraldo · Valentina Zapata Acosta · Sebastián Granda Giraldo

---

## Arquitectura

```
                 REST/HTTPS (metadatos, auth)
   ┌─────────┐ ─────────────────────────────▶ ┌──────────────┐
   │ Cliente │                                │ ControlNode  │  metadatos, usuarios,
   │  (CLI)  │ ◀───────── plan de bloques ─── │  (maestro)   │  locks, re-replicación
   └────┬────┘                                └──────┬───────┘
        │ PUT/GET /block/{id}                        │ register / heartbeat
        │ (datos directo a los nodos,                │ verificación, copia de
        │  con token HMAC por bloque)                │ bloques, limpieza
        ▼                                            ▼
   ┌──────────┐      ┌──────────┐      ┌──────────┐
   │DataNode 1│      │DataNode 2│      │DataNode 3│   bloques cifrados AES-256-GCM
   └──────────┘      └──────────┘      └──────────┘
```

| Componente | Qué hace |
|---|---|
| **ControlNode** (`controlnode/`) | Guarda el árbol de directorios, la tabla archivo → bloques → réplicas, usuarios, API keys y 2FA. Decide dónde va cada bloque (round-robin), maneja `open/lock/read/write/close`, detecta DataNodes caídos por heartbeat y re-replica los bloques que quedaron con menos copias. |
| **DataNode** (`datanode/`) | Guarda bloques en disco cifrados con AES-256-GCM. Solo acepta operaciones que traigan un token HMAC válido para ese bloque. Se registra y manda heartbeat cada 5 s. |
| **Cliente** (`client/dfsha_cli.py`) | CLI y shell interactivo tipo Linux (`ls`, `cd`, `mkdir`, `put`, `get`, …). Para `put`/`get` habla con el ControlNode solo para pedir el plan y luego transfiere los datos directamente con los DataNodes. |

Todo está escrito en **Python 3.11 + FastAPI** y la comunicación es **REST sobre HTTP/HTTPS**.

---

## Requisitos

- Docker y Docker Compose (para correr el clúster)
- Python 3.10+ y `pip install -r client/requirements.txt` (para el cliente)
- Para las pruebas: `pip install -r controlnode/requirements.txt -r datanode/requirements.txt pytest`

---

## Correr el clúster en una sola máquina

```bash
docker compose up --build -d
docker compose ps
```

Esto levanta 1 ControlNode (puerto 8000) y 3 DataNodes (8001, 8002, 8003) con factor de replicación 2.

### Con TLS (HTTPS en todas las conexiones)

```bash
./scripts/gen_certs.sh                       # crea una CA propia y el certificado de los nodos
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build -d

export DFSHA_CONTROL_URL=https://localhost:8000
export DFSHA_CA_CERT=$PWD/certs/ca.crt       # el cliente confía en nuestra CA
```

### Variables de configuración

| Variable | Default | Para qué |
|---|---|---|
| `DFSHA_INTERNAL_SECRET` | valor de desarrollo | Secreto compartido ControlNode ↔ DataNodes (firma de tokens de bloque y registro). **Cambiarlo en AWS.** |
| `DFSHA_BLOCK_ENCRYPTION_KEY` | derivada del secreto | Llave AES de 32 bytes en base64 para cifrar bloques en disco |
| `DFSHA_TOTP_ENCRYPTION_KEY` | derivada del secreto | Llave Fernet para guardar cifrados los secretos 2FA |
| `REPLICATION_FACTOR` | 2 | Copias de cada bloque |
| `HEARTBEAT_TIMEOUT` | 15 | Segundos sin heartbeat para dar un DataNode por caído |
| `REPAIR_INTERVAL` | 10 | Cada cuántos segundos se revisan bloques sub-replicados |
| `ORPHAN_GRACE` | 120 | Edad mínima (s) de un bloque huérfano antes de borrarlo |
| `DFSHA_VALE_PASSWORD` / `DFSHA_ADMIN_PASSWORD` | `vale123` / `admin123` | Usuarios iniciales |

Generar llaves propias:

```bash
python3 -c "import secrets;print(secrets.token_urlsafe(32))"                                  # INTERNAL_SECRET
python3 -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"         # BLOCK / TOTP key
```

---

## Despliegue en AWS Academy (varias VMs)

1. Crear 4 instancias EC2 Ubuntu (1 ControlNode + 3 DataNodes) en el mismo VPC e instalar Docker.
2. Security group: abrir el puerto 8000 (ControlNode) y el puerto de cada DataNode hacia los clientes; entre las VMs permitir tráfico interno.
3. En **todas** las VMs exportar el mismo secreto y llave:
   ```bash
   export DFSHA_INTERNAL_SECRET=...  DFSHA_BLOCK_ENCRYPTION_KEY=...
   ```
4. Si se usa TLS: correr `./scripts/gen_certs.sh <ip_publica_control> <ip_publica_dn1> ...` en una máquina y copiar la carpeta `certs/` a todas.
5. VM del ControlNode:
   ```bash
   docker build -t dfsha-control ./controlnode
   docker run -d --restart unless-stopped -p 8000:8000 -v dfsha-state:/app/data \
     -e DFSHA_INTERNAL_SECRET -e REPLICATION_FACTOR=2 dfsha-control
   ```
6. Cada VM de DataNode (cambiando el id y la IP):
   ```bash
   docker build -t dfsha-datanode ./datanode
   docker run -d --restart unless-stopped -p 8001:8000 -v dfsha-blocks:/app/blocks \
     -e DFSHA_INTERNAL_SECRET -e DFSHA_BLOCK_ENCRYPTION_KEY \
     -e CONTROL_URL=http://<ip_privada_control>:8000 \
     -e DATANODE_ID=dn1 \
     -e DATANODE_URL=http://<ip_publica_dn1>:8001 \
     -e DATANODE_INTERNAL_URL=http://<ip_privada_dn1>:8001 \
     dfsha-datanode
   ```
   `DATANODE_URL` es la dirección que reciben los clientes (pública) y `DATANODE_INTERNAL_URL` la que usa el ControlNode (privada). Para TLS se usa `https://`, se monta `-v $PWD/certs:/certs:ro` y se agregan `-e TLS_CERT=/certs/node.crt -e TLS_KEY=/certs/node.key -e SSL_CERT_FILE=/certs/ca.crt`.

---

## Uso del cliente

```bash
cd client
pip install -r requirements.txt
export DFSHA_CONTROL_URL=http://localhost:8000
export DFSHA_USER=vale DFSHA_PASSWORD=vale123

python dfsha_cli.py login
python dfsha_cli.py mkdir /docs
python dfsha_cli.py put ./video.mp4 /docs/video.mp4
python dfsha_cli.py ls /docs
python dfsha_cli.py get /docs/video.mp4 ./copia.mp4
python dfsha_cli.py rm /docs/video.mp4
python dfsha_cli.py shell          # shell interactivo con cd, ls, put, get, status...
```

Acceso por handle (RF3):

```bash
python dfsha_cli.py open /docs/notas.txt --mode r+      # devuelve un handle
python dfsha_cli.py lock   <handle>
python dfsha_cli.py write  <handle> 0 ./parche.txt
python dfsha_cli.py read   <handle> 0 1024 ./salida.txt
python dfsha_cli.py unlock <handle>
python dfsha_cli.py close  <handle>
```

Seguridad del usuario:

```bash
python dfsha_cli.py totp-setup                 # muestra el secreto / URI para Google Authenticator
python dfsha_cli.py totp-confirm 123456
export DFSHA_TOTP_CODE=654321                  # en cada llamada mientras 2FA esté activo
python dfsha_cli.py api-key-create --name laptop
export DFSHA_API_KEY=...                       # alternativa a usuario/contraseña
```

Estado del clúster (solo admin):

```bash
DFSHA_USER=admin DFSHA_PASSWORD=admin123 python dfsha_cli.py status
```

---

## API

Autenticación: HTTP Basic (`usuario:contraseña`) + `X-TOTP-Code` si tiene 2FA, o `X-API-Key`.

### ControlNode

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/auth/login` | Verifica credenciales |
| POST / DELETE | `/auth/users`, `/auth/users/{u}` | Crear / borrar usuario (admin) |
| POST | `/auth/totp/setup`, `/auth/totp/confirm` · DELETE `/auth/totp` | 2FA TOTP |
| POST / DELETE | `/auth/api-keys`, `/auth/api-keys/{id}` | API keys |
| GET | `/fs/ls?path=` | Listar directorio |
| POST | `/fs/mkdir` | Crear directorio |
| DELETE | `/fs/rmdir?path=` · `/fs/rm?path=` | Borrar directorio vacío / archivo |
| POST | `/fs/create` | Reserva el archivo y devuelve el plan de bloques (DataNodes + tokens) |
| POST | `/fs/commit` · DELETE `/fs/abort` | Confirma la subida (verifica todas las réplicas) o la cancela |
| GET | `/fs/locate?path=` | Ubicación de los bloques para descargar |
| POST | `/fs/open`, `/fs/read`, `/fs/write`, `/fs/lock`, `/fs/unlock`, `/fs/close` | Acceso por handle |
| GET | `/admin/cluster` | Estado de nodos, bloques, sub-replicados y mantenimiento (admin) |
| POST | `/datanode/register`, `/datanode/heartbeat` | Uso interno (header `X-Internal-Secret`) |
| GET | `/datanode/list`, `/health` | Nodos registrados / salud |

### DataNode

| Método | Ruta | Descripción |
|---|---|---|
| PUT / GET / DELETE | `/block/{id}` | Guardar / leer / borrar bloque (header `X-Block-Token`) |
| GET | `/block/{id}/status` | Si existe y su tamaño (lo usa el commit) |
| GET | `/blocks` | Lista de bloques con su edad (interno, para limpieza) |
| GET | `/health` | Salud y número de bloques |

La documentación interactiva de FastAPI queda en `http://<nodo>:<puerto>/docs`.

---

## Pruebas

Las pruebas levantan solas un clúster local (sin Docker) en los puertos 18000–18003:

```bash
pip install -r controlnode/requirements.txt -r datanode/requirements.txt pytest
python -m pytest tests -v                       # HTTP
./scripts/gen_certs.sh && DFSHA_TEST_TLS=1 python -m pytest tests -v   # todo por HTTPS
```

Cubren: subida/bajada de archivos multibloque, reparto y réplicas, `mkdir/rmdir/rm`, cifrado en disco, control de acceso entre usuarios, tokens de bloque, 2FA y API keys, `open/lock/write/read`, lectura con un DataNode caído, re-replicación automática, limpieza de bloques viejos cuando un nodo vuelve y persistencia del ControlNode tras reiniciarlo.

Medición de rendimiento:

```bash
python tests/benchmark.py                 # clúster local temporal
python tests/benchmark.py --remote        # contra el clúster definido en DFSHA_CONTROL_URL
```

---

## Estructura

```
controlnode/   ControlNode (FastAPI) + Dockerfile
datanode/      DataNode (FastAPI) + Dockerfile
client/        CLI dfsha_cli.py
scripts/       gen_certs.sh (CA y certificados TLS)
tests/         pruebas de integración y benchmark
docs/          informe técnico y guion del video
docker-compose.yml / docker-compose.tls.yml
```

## Limitaciones conocidas

- El ControlNode es único: si se cae, los datos no se pierden (su estado se guarda en disco y los DataNodes se vuelven a registrar solos al reiniciarlo), pero mientras está abajo no se pueden hacer operaciones. Una mejora sería un ControlNode secundario con la metadata replicada (p. ej. con Raft).
- `write` sobre un archivo abierto reescribe el archivo completo con bloques nuevos; es correcto pero no eficiente para archivos muy grandes.
- El cliente sube cada réplica por su cuenta (no hay pipeline DataNode → DataNode como en HDFS).
