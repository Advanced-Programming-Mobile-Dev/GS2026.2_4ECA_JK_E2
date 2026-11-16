#!/usr/bin/env python3
"""
Simulador de dispositivo de campo (sensor) da Rede Vila Aurora.

Publica telemetria via MQTT sobre TLS com certificado próprio (mTLS).
Configuração por variáveis de ambiente:

    DEVICE_ID     identificador único (igual ao CN do certificado)
    SPACE         espaço comunitário (ubs, escola, centro, horta, abrigo)
    SENSOR        modelo do sensor (ver SENSOR_MODELS)
    BROKER_HOST   host do broker da borda
    BROKER_PORT   porta TLS (padrão 8883)
    CERT_DIR      pasta com <DEVICE_ID>.crt, <DEVICE_ID>.key e ca.crt
    INTERVAL      segundos entre leituras (padrão 5)
"""
from __future__ import annotations

import json
import logging
import os
import random
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

# Modelos simples: valor = base + ruído gaussiano. A etapa 2 amplia esta tabela.
SENSOR_MODELS = {
    "camara_fria": {"unit": "C", "base": 5.0, "noise": 0.4},        # faixa segura 2–8 °C
    "nivel_reservatorio": {"unit": "%", "base": 70.0, "noise": 2.0},
}

DEVICE_ID = os.environ["DEVICE_ID"]
SPACE = os.environ["SPACE"]
SENSOR = os.environ["SENSOR"]
BROKER_HOST = os.environ.get("BROKER_HOST", "localhost")
BROKER_PORT = int(os.environ.get("BROKER_PORT", "8883"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
INTERVAL = float(os.environ.get("INTERVAL", "5"))

TOPIC = f"va/{SPACE}/telemetry/{DEVICE_ID}"

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s device=" + DEVICE_ID + " %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("device")


def build_client() -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=DEVICE_ID)
    client.tls_set(
        ca_certs=str(CERT_DIR / "ca.crt"),
        certfile=str(CERT_DIR / f"{DEVICE_ID}.crt"),
        keyfile=str(CERT_DIR / f"{DEVICE_ID}.key"),
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,  # TLS 1.2+ com verificação de hostname
    )
    client.reconnect_delay_set(min_delay=1, max_delay=30)

    def on_connect(_c, _u, _flags, reason_code, _props):
        if reason_code.is_failure:
            log.error("conexao recusada pelo broker: %s", reason_code)
        else:
            log.info("conectado com mTLS a %s:%s", BROKER_HOST, BROKER_PORT)

    def on_disconnect(_c, _u, _flags, reason_code, _props):
        log.warning("desconectado: %s", reason_code)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    return client


def reading() -> dict:
    model = SENSOR_MODELS[SENSOR]
    return {
        "msg_id": str(uuid.uuid4()),
        "device_id": DEVICE_ID,
        "space": SPACE,
        "sensor": SENSOR,
        "value": round(random.gauss(model["base"], model["noise"]), 2),
        "unit": model["unit"],
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def main() -> None:
    if SENSOR not in SENSOR_MODELS:
        raise SystemExit(f"SENSOR desconhecido: {SENSOR}")
    client = build_client()
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
            break
        except (OSError, ssl.SSLError) as exc:
            log.error("falha ao conectar (%s); nova tentativa em 5 s", exc)
            time.sleep(5)

    client.loop_start()
    try:
        while True:
            msg = reading()
            client.publish(TOPIC, json.dumps(msg), qos=1)
            log.info("publicado topic=%s value=%s%s", TOPIC, msg["value"], msg["unit"])
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
