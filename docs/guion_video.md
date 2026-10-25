# Guion del video — DFSha (12–14 min)

Repartan los bloques entre los integrantes. Tengan el clúster ya levantado antes de grabar (`docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d`) y dos terminales abiertas: una con el cliente (usuario `vale`) y otra para `docker` y el usuario `admin`.

## 1. Presentación (0:00 – 1:00)
- Nombres, curso y qué es DFSha en una frase: "un sistema de archivos distribuido por bloques, estilo HDFS, con réplicas, recuperación automática y cifrado".
- Mostrar la portada del informe.

## 2. Arquitectura (1:00 – 3:30)
- Mostrar la Figura 1 del informe. Explicar los tres roles con la analogía: bibliotecario (ControlNode), bodegas (DataNodes), usuario (cliente).
- Remarcar que los datos van directo del cliente a los DataNodes; el ControlNode solo da el "mapa".
- Mencionar bloques de 4 MB, factor de replicación 2 y round-robin.

## 3. Demo básica (3:30 – 6:00)
```bash
python dfsha_cli.py login
python dfsha_cli.py mkdir /demo
python dfsha_cli.py put video.mp4 /demo/video.mp4     # mostrar los bloques y a qué nodos van
python dfsha_cli.py ls /demo
python dfsha_cli.py get /demo/video.mp4 copia.mp4
sha256sum video.mp4 copia.mp4                          # mismo hash = archivo íntegro
python dfsha_cli.py shell                              # cd /demo, ls, status...
```

## 4. Alta disponibilidad (6:00 – 9:00)
```bash
# 3 nodos activos:
DFSHA_USER=admin DFSHA_PASSWORD=admin123 python dfsha_cli.py status
docker compose stop datanode1                                          # "se cae un servidor"
python dfsha_cli.py get /demo/video.mp4 copia2.mp4                     # sigue funcionando
# esperar ~25 s
# dn1 CAIDO, sub-replicados = 0, bloques re-replicados > 0:
DFSHA_USER=admin DFSHA_PASSWORD=admin123 python dfsha_cli.py status
# vuelve y se limpian sus bloques viejos:
docker compose start datanode1
```
- Explicar heartbeat, re-replicación y limpieza de huérfanos (Figura 3).

## 5. Consistencia y seguridad (9:00 – 11:30)
- `open --mode r+` + `lock` en una terminal, intentar `get` desde la otra → error 409 (archivo bloqueado).
- Con otro usuario intentar leer `/demo/video.mp4` → 403.
- `docker compose exec datanode2 sh -c "head -c 80 /app/blocks/*"` → se ve basura cifrada que empieza por `DFSB1`.
- Mostrar `https://` en las URLs y 2FA: `totp-setup` + `totp-confirm` con el celular.

## 6. Pruebas y resultados (11:30 – 13:00)
- Correr `python -m pytest tests -v` (o mostrar la salida ya grabada: 15 pruebas OK).
- Mostrar la Figura 4 y la tabla de recuperación del informe; una conclusión por punto.

## 7. Cierre (13:00 – 14:00)
- Limitaciones (ControlNode único) y cómo lo mejorarían (ControlNode de respaldo con Raft).
- Link al repositorio.
