# Switchboard — free-tier container image.
# Pure stdlib app: no pip dependencies needed.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app
COPY server.py ed25519.py evm_crypto.py client_example.py ./
COPY assets/ ./assets/

# SQLite lives here; mount a volume at /data on hosts that support it (Fly.io).
ENV SWITCHBOARD_DB=/data/switchboard.db
VOLUME /data

EXPOSE 8080
CMD ["python3", "server.py"]
