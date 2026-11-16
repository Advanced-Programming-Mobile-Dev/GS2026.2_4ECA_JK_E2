#!/usr/bin/env python3
"""
Serviço de INGESTÃO da nuvem (Rede Vila Aurora).

- Escuta só dentro da VPN (compartilha a interface do gateway WireGuard,
  IP 10.13.13.1) em HTTPS com mTLS: só agentes de borda com certificado da
  CA do projeto, não revogado (CRL), conseguem falar com ele.
- Autorização pela identidade: o agente edge-<espaco>-agent só pode enviar
  eventos do próprio espaço.
- Gravação idempotente no PostgreSQL (ON CONFLICT DO NOTHING pelo msg_id):
  reenvios do buffer após uma queda não duplicam dados (reconciliação).
- Consultas sempre parametrizadas; usuário de banco só com INSERT.

Endpoints:  GET /health   POST /ingest  {"agent": "...", "messages": [...]}
"""
from __future__ import annotations

import json
import logging
import os
import re
import ssl
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

LISTEN = os.environ.get("LISTEN", "10.13.13.1")
PORT = int(os.environ.get("PORT", "8443"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
SERVER_ID = os.environ.get("SERVER_ID", "cloud-ingest")
CRL_FILE = Path(os.environ.get("CRL_FILE", "/crl/crl.pem"))
DB_DSN = (f"host={os.environ.get('DB_HOST', 'postgres')} dbname={os.environ.get('DB_NAME', 'vilaaurora')} "
          f"user={os.environ.get('DB_USER', 'ingest_writer')} password={os.environ['DB_PASSWORD']} "
          f"connect_timeout=3")

MAX_BODY = 5 * 1024 * 1024
MAX_MESSAGES = 1000
KINDS = {"telemetry", "alarm", "command", "access"}
ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
AGENT_RE = re.compile(r"^edge-([a-z]+)-agent$")

INSERT_SQL = """
    INSERT INTO events (msg_id, kind, space, device_id, sensor, value, unit, ts, agent, data)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (msg_id) DO NOTHING
"""

logging.Formatter.converter = time.gmtime
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)sZ %(levelname)s service=" + SERVER_ID + " %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("ingest")


def validate(msg: dict, space: str, agent: str) -> tuple | None:
    """Retorna a tupla de parâmetros do INSERT ou None se a mensagem for inválida."""
    try:
        msg_id = str(uuid.UUID(str(msg["msg_id"])))
        kind = msg["kind"]
        device = msg["device_id"]
        if kind not in KINDS or not ID_RE.match(device) or msg.get("space") != space:
            return None
        value = msg.get("value")
        value = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        return (msg_id, kind, space, device, str(msg.get("sensor", ""))[:40], value,
                str(msg.get("unit", ""))[:16] or None, msg["ts"], agent, Jsonb(msg))
    except (KeyError, ValueError, TypeError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "VilaAuroraIngest/1.0"
    sys_version = ""

    def log_message(self, fmt, *args):   # silencia o log padrão (usamos o nosso)
        pass

    def peer_cn(self) -> str:
        cert = self.connection.getpeercert() or {}
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return ""

    def reply(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ok"})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/ingest":
            return self.reply(404, {"error": "not found"})
        cn = self.peer_cn()
        match = AGENT_RE.match(cn)
        if not match:
            log.warning("NEGADO identidade=%s ip=%s motivo=nao_e_agente_de_borda", cn, self.client_address[0])
            return self.reply(403, {"error": "forbidden"})
        space = match.group(1)

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            return self.reply(413, {"error": "payload size"})
        try:
            body = json.loads(self.rfile.read(length))
            messages = body["messages"]
            if not isinstance(messages, list) or len(messages) > MAX_MESSAGES:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"error": "invalid body"})

        inserted = duplicates = rejected = 0
        try:
            with psycopg.connect(DB_DSN) as conn, conn.cursor() as cur:
                for msg in messages:
                    params = validate(msg, space, cn) if isinstance(msg, dict) else None
                    if params is None:
                        rejected += 1
                        continue
                    cur.execute(INSERT_SQL, params)
                    if cur.rowcount == 1:
                        inserted += 1
                    else:
                        duplicates += 1
        except psycopg.Error as exc:
            log.error("banco indisponivel: %s", exc.__class__.__name__)
            return self.reply(503, {"error": "database unavailable"})

        level = logging.WARNING if rejected else logging.INFO
        log.log(level, "lote agente=%s recebidas=%d novas=%d duplicadas=%d rejeitadas=%d",
                cn, len(messages), inserted, duplicates, rejected)
        self.reply(200, {"inserted": inserted, "duplicates": duplicates, "rejected": rejected})


def tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_DIR / f"{SERVER_ID}.crt", CERT_DIR / f"{SERVER_ID}.key")
    ctx.load_verify_locations(CERT_DIR / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED          # mTLS
    if CRL_FILE.is_file():
        ctx.load_verify_locations(CRL_FILE)
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF   # certificados revogados são recusados
    return ctx


class TLSServer(ThreadingHTTPServer):
    """Faz o handshake TLS de cada conexão e registra as recusas (para o SIEM)."""
    daemon_threads = True

    def __init__(self, addr, handler, ctx: ssl.SSLContext):
        super().__init__(addr, handler)
        self.ctx = ctx

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(10)
        try:
            return self.ctx.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError) as exc:
            log.warning("TLS RECUSADO ip=%s motivo=%s", addr[0], getattr(exc, "reason", None) or exc)
            sock.close()
            raise


def main() -> None:
    # Escuta SÓ no IP da VPN: o container compartilha a rede do gateway, que
    # também tem interfaces nas redes WAN; sem isso, daria para chegar à
    # ingestão sem passar pelo túnel. Espera a interface wg0 subir.
    while True:
        try:
            server = TLSServer((LISTEN, PORT), Handler, tls_context())
            break
        except OSError as exc:
            log.warning("aguardando o endereco %s (interface da VPN): %s", LISTEN, exc)
            time.sleep(2)
    log.info("ingestao ouvindo em https://%s:%d (mTLS, CRL=%s)", LISTEN, PORT, CRL_FILE.is_file())
    server.serve_forever()


if __name__ == "__main__":
    main()
