#!/usr/bin/env python3
"""
Simulador da camada de CAMPO de um espaço comunitário da Rede Vila Aurora.

Um container por espaço; dentro dele, uma thread por dispositivo. Cada
dispositivo usa o PRÓPRIO certificado X.509 (mTLS) e publica só no próprio
tópico: va/<espaco>/telemetry/<device_id>  (RT-04).

Variáveis de ambiente:
    SPACE         centro | escola | ubs | horta | abrigo
    BROKER_HOST   broker da borda do espaço (ex.: edge-ubs-broker)
    BROKER_PORT   porta TLS (padrão 8883)
    CERT_ROOT     pasta com uma subpasta por dispositivo (padrão /certs)
    DEVICES_FILE  inventário (padrão /app/devices.json)
    BADGES_FILE   crachás sintéticos para os leitores RFID (padrão /data/crachas.csv)
    INTERVAL      segundos entre leituras dos sensores (padrão 5)
"""
from __future__ import annotations

import csv
import json
import logging
import math
import os
import random
import ssl
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

SPACE = os.environ["SPACE"]
BROKER_HOST = os.environ.get("BROKER_HOST", f"edge-{SPACE}-broker")
BROKER_PORT = int(os.environ.get("BROKER_PORT", "8883"))
CERT_ROOT = Path(os.environ.get("CERT_ROOT", "/certs"))
DEVICES_FILE = Path(os.environ.get("DEVICES_FILE", "/app/devices.json"))
BADGES_FILE = Path(os.environ.get("BADGES_FILE", "/data/crachas.csv"))
INTERVAL = float(os.environ.get("INTERVAL", "5"))

LOCAL_TZ = timezone(timedelta(hours=-3))  # Serra Clara (SP), usado só na curva solar

# ------------------------------------------------------------------ modelos
# Leituras seguem um processo de reversão à média (AR(1)):
#     x[t+1] = x[t] + theta * (base - x[t]) + sigma * N(0, 1)
# limitado ao intervalo [min, max]. Fica realista (sem saltos absurdos) e
# deixa a etapa de IA injetar anomalias depois.
SENSOR_MODELS = {
    "camara_fria":    {"unit": "C",    "base": 5.0,   "sigma": 0.15, "min": -5,  "max": 30},
    "turbidez":       {"unit": "NTU",  "base": 0.8,   "sigma": 0.05, "min": 0,   "max": 100},
    "cloro_residual": {"unit": "mg/L", "base": 1.0,   "sigma": 0.04, "min": 0,   "max": 5},
    "bateria_soc":    {"unit": "%",    "base": 80.0,  "sigma": 0.5,  "min": 0,   "max": 100},
    "geracao_solar":  {"unit": "kW",   "base": 0.0,   "sigma": 0.1,  "min": 0,   "max": 6},
    "co2":            {"unit": "ppm",  "base": 600.0, "sigma": 15.0, "min": 350, "max": 5000},
    "umidade_solo":   {"unit": "%",    "base": 45.0,  "sigma": 0.8,  "min": 0,   "max": 100},
    "nivel_cisterna": {"unit": "%",    "base": 60.0,  "sigma": 0.5,  "min": 0,   "max": 100},
    "alagamento":     {"unit": "cm",   "base": 0.0,   "sigma": 0.2,  "min": 0,   "max": 200},
    "umidade_ar":     {"unit": "%",    "base": 65.0,  "sigma": 1.0,  "min": 0,   "max": 100},
}
THETA = 0.1

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s space=" + SPACE + " %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("field")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def solar_base() -> float:
    """Geração fotovoltaica: meia senoide entre 6h e 18h (horário local), pico 5 kW."""
    hour = datetime.now(LOCAL_TZ)
    h = hour.hour + hour.minute / 60
    return 5.0 * math.sin(math.pi * (h - 6) / 12) if 6 <= h <= 18 else 0.0


def load_badges() -> list[str]:
    if not BADGES_FILE.exists():
        log.warning("arquivo de crachás não encontrado (%s); leitores RFID usarão UIDs aleatórios", BADGES_FILE)
        return []
    with BADGES_FILE.open(encoding="utf-8") as fh:
        return [row["badge_uid"] for row in csv.DictReader(fh)]


# ---------------------------------------------------------------- dispositivo
class Device(threading.Thread):
    def __init__(self, device_id: str, sensor: str, badges: list[str]):
        super().__init__(name=device_id, daemon=True)
        self.device_id = device_id
        self.sensor = sensor
        self.badges = badges
        self.topic = f"va/{SPACE}/telemetry/{device_id}"
        model = SENSOR_MODELS.get(sensor)
        self.value = model["base"] if model else None
        self.client = self._build_client()

    def _build_client(self) -> mqtt.Client:
        folder = CERT_ROOT / self.device_id
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=self.device_id)
        client.tls_set(
            ca_certs=str(folder / "ca.crt"),
            certfile=str(folder / f"{self.device_id}.crt"),
            keyfile=str(folder / f"{self.device_id}.key"),
            cert_reqs=ssl.CERT_REQUIRED,
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        return client

    def _on_connect(self, _c, _u, _f, reason_code, _p):
        if reason_code.is_failure:
            log.error("device=%s conexao recusada: %s", self.device_id, reason_code)
        else:
            log.info("device=%s conectado com mTLS a %s:%s", self.device_id, BROKER_HOST, BROKER_PORT)

    def _on_disconnect(self, _c, _u, _f, reason_code, _p):
        log.warning("device=%s desconectado: %s", self.device_id, reason_code)

    # -- leituras
    def next_reading(self) -> dict:
        msg = {"msg_id": str(uuid.uuid4()), "device_id": self.device_id, "space": SPACE,
               "sensor": self.sensor, "ts": utc_iso()}
        if self.sensor == "rfid":
            known = self.badges and random.random() < 0.9
            msg["badge_uid"] = (random.choice(self.badges) if known
                                else "".join(random.choice("0123456789ABCDEF") for _ in range(8)))
            msg["event"] = "badge_read"
            return msg

        model = SENSOR_MODELS[self.sensor]
        base = solar_base() if self.sensor == "geracao_solar" else model["base"]
        self.value += THETA * (base - self.value) + random.gauss(0, model["sigma"])
        self.value = min(max(self.value, model["min"]), model["max"])
        msg["value"] = round(self.value, 2)
        msg["unit"] = model["unit"]
        return msg

    def wait_time(self) -> float:
        # leitores RFID são orientados a evento: leituras espaçadas e irregulares
        return random.uniform(10, 40) if self.sensor == "rfid" else INTERVAL

    def run(self) -> None:
        while True:
            try:
                self.client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
                break
            except (OSError, ssl.SSLError) as exc:
                log.error("device=%s falha ao conectar (%s); nova tentativa em 5 s", self.device_id, exc)
                time.sleep(5)
        self.client.loop_start()
        time.sleep(random.uniform(0, 2))  # desalinha as publicações
        while True:
            msg = self.next_reading()
            self.client.publish(self.topic, json.dumps(msg), qos=1)
            shown = msg.get("value", msg.get("badge_uid"))
            log.info("device=%s publicado %s=%s%s", self.device_id, self.sensor, shown, msg.get("unit", ""))
            time.sleep(self.wait_time())


def main() -> None:
    inventory = json.loads(DEVICES_FILE.read_text(encoding="utf-8"))
    devices = inventory.get(SPACE)
    if not devices:
        raise SystemExit(f"Nenhum dispositivo para o espaço '{SPACE}' em {DEVICES_FILE}")
    badges = load_badges()
    threads = []
    for d in devices:
        if d["sensor"] != "rfid" and d["sensor"] not in SENSOR_MODELS:
            raise SystemExit(f"Sensor desconhecido: {d['sensor']}")
        t = Device(d["id"], d["sensor"], badges)
        t.start()
        threads.append(t)
    log.info("%d dispositivos simulados iniciados", len(threads))
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
