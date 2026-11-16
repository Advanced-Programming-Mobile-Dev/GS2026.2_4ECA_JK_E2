#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

HMAC_FILE = Path(os.environ.get("HMAC_FILE", "/hmac/escola-nivel-01.json"))
PUBLIC_BROKER = os.environ.get("PUBLIC_BROKER", "broker.hivemq.com")
PUBLIC_PORT = int(os.environ.get("PUBLIC_PORT", "8883"))
EDGE_HOST = os.environ.get("EDGE_HOST", "edge-escola-broker")
EDGE_PORT = int(os.environ.get("EDGE_PORT", "8883"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
BRIDGE_ID = os.environ.get("BRIDGE_ID", "escola-wokwi-bridge")
MAX_SKEW_S = int(os.environ.get("MAX_SKEW_S", "300"))

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s bridge=" + BRIDGE_ID + " %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("bridge")

class Validator:
    """Valida o envelope {"body": "<json>", "sig": "<hex>"} enviado pelo ESP32."""

    def __init__(self, device_id: str, key: bytes, max_skew_s: int):
        self.device_id = device_id
        self.key = key
        self.max_skew_s = max_skew_s
        self.last_seq: dict[str, int] = {}   # boot_id -> maior seq aceito

    def check(self, raw: bytes, now: datetime | None = None) -> tuple[dict | None, str]:
        now = now or datetime.now(timezone.utc)
        try:
            envelope = json.loads(raw)
            body_str, sig = envelope["body"], envelope["sig"]
        except (ValueError, KeyError, TypeError):
            return None, "formato invalido"

        expected = hmac.new(self.key, body_str.encode(), hashlib.sha256).hexdigest()
        # comparação em tempo constante (evita ataque de temporização)
        if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
            return None, "assinatura HMAC invalida"

        try:
            body = json.loads(body_str)
            boot_id, seq = str(body["boot_id"]), int(body["seq"])
            ts = datetime.fromisoformat(body["ts"].replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError):
            return None, "corpo invalido"

        if body.get("device_id") != self.device_id:
            return None, f"device_id inesperado: {body.get('device_id')}"
        skew = abs((now - ts).total_seconds())
        if skew > self.max_skew_s:
            return None, f"fora da janela de tempo ({skew:.0f}s)"
        if seq <= self.last_seq.get(boot_id, 0):
            return None, f"replay detectado (boot={boot_id} seq={seq})"

        self.last_seq[boot_id] = seq
        return body, "ok"


# ---------------------------------------------------------------------- main
def edge_client() -> mqtt.Client:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=BRIDGE_ID)
    c.tls_set(
        ca_certs=str(CERT_DIR / "ca.crt"),
        certfile=str(CERT_DIR / f"{BRIDGE_ID}.crt"),
        keyfile=str(CERT_DIR / f"{BRIDGE_ID}.key"),
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    c.reconnect_delay_set(1, 30)
    c.on_connect = lambda *_a: log.info("conectado ao broker da borda %s:%s (mTLS)", EDGE_HOST, EDGE_PORT)
    return c


def main() -> None:
    cfg = json.loads(HMAC_FILE.read_text())
    device_id = cfg["device_id"]
    public_topic = f"{cfg['topic_prefix']}/escola/{device_id}"
    edge_topic = f"va/escola/telemetry/{device_id}"
    validator = Validator(device_id, bytes.fromhex(cfg["key_hex"]), MAX_SKEW_S)
    stats = {"aceitas": 0, "rejeitadas": 0}

    edge = edge_client()
    while True:
        try:
            edge.connect(EDGE_HOST, EDGE_PORT, keepalive=30)
            break
        except (OSError, ssl.SSLError) as exc:
            log.error("borda indisponível (%s); nova tentativa em 5 s", exc)
            time.sleep(5)
    edge.loop_start()

    public = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                         client_id=f"va-bridge-{uuid.uuid4().hex[:8]}")
    # TLS com verificação do certificado do broker público (CAs do sistema)
    public.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    public.reconnect_delay_set(1, 30)

    def on_public_connect(c, _u, _f, rc, _p):
        if rc.is_failure:
            log.error("broker público recusou: %s", rc)
            return
        c.subscribe(public_topic, qos=0)
        log.info("assinando %s em %s:%s", public_topic, PUBLIC_BROKER, PUBLIC_PORT)

    def on_public_message(_c, _u, msg):
        body, reason = validator.check(msg.payload)
        if body is None:
            stats["rejeitadas"] += 1
            log.warning("REJEITADA motivo=\"%s\" bytes=%d total_rejeitadas=%d",
                        reason, len(msg.payload), stats["rejeitadas"])
            return
        body["msg_id"] = str(uuid.uuid4())
        body["via"] = "wokwi-bridge"
        body["auth"] = "hmac-sha256"
        edge.publish(edge_topic, json.dumps(body), qos=1)
        stats["aceitas"] += 1
        log.info("ACEITA seq=%s nivel=%s%% -> %s (total_aceitas=%d)",
                 body["seq"], body.get("value"), edge_topic, stats["aceitas"])

    public.on_connect = on_public_connect
    public.on_message = on_public_message
    while True:
        try:
            public.connect(PUBLIC_BROKER, PUBLIC_PORT, keepalive=60)
            break
        except (OSError, ssl.SSLError) as exc:
            log.error("broker público indisponível (%s); nova tentativa em 5 s", exc)
            time.sleep(5)
    public.loop_forever()


if __name__ == "__main__":
    main()
