#!/usr/bin/env bash
# Genera una CA propia y un certificado para los nodos de DFSha.
# Uso: ./scripts/gen_certs.sh [IP_PUBLICA_O_DNS ...]
# Ej:  ./scripts/gen_certs.sh 54.210.10.20 ec2-54-210-10-20.compute-1.amazonaws.com
set -euo pipefail

OUT="$(dirname "$0")/../certs"
mkdir -p "$OUT"
cd "$OUT"

# nombres que usan los contenedores entre si + localhost
SAN="DNS:localhost,DNS:controlnode,DNS:datanode1,DNS:datanode2,DNS:datanode3,IP:127.0.0.1"
for extra in "$@"; do
  if [[ "$extra" =~ ^[0-9.]+$ ]]; then SAN="$SAN,IP:$extra"; else SAN="$SAN,DNS:$extra"; fi
done

if [ ! -f ca.key ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
    -keyout ca.key -out ca.crt -subj "/CN=DFSha CA"
fi

openssl req -newkey rsa:2048 -nodes -keyout node.key -out node.csr -subj "/CN=dfsha-node"
printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$SAN" > node.ext
openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out node.crt -extfile node.ext
rm -f node.csr node.ext
chmod 600 ca.key node.key

echo "Certificados en $(pwd):"
ls -1
echo "SAN: $SAN"
