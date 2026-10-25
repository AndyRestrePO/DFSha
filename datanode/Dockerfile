FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# Si se montan certificados (TLS_CERT / TLS_KEY) el nodo arranca en HTTPS,
# si no, queda en HTTP como en los hitos anteriores.
CMD ["sh", "-c", "if [ -n \"$TLS_CERT\" ] && [ -f \"$TLS_CERT\" ]; then exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --ssl-certfile \"$TLS_CERT\" --ssl-keyfile \"$TLS_KEY\"; else exec uvicorn app.main:app --host 0.0.0.0 --port 8000; fi"]
