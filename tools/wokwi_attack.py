#!/usr/bin/env python3
"""
Ataques ao trecho Wokwi -> broker público, para mostrar que a ponte rejeita.

Pior caso assumido: o atacante descobriu o tópico (o broker é público), mas
NÃO tem a chave HMAC do ESP32. Este script lê apenas o 'topic_prefix'.

Modos:
  forge   publica uma leitura falsa (nível 0 %) com assinatura inventada
  tamper  captura uma mensagem legítima, altera o valor e reenvia
  replay  captura uma mensagem legítima e a reenvia sem alterações

Uso (dentro do container 'tools'):
    python wokwi_attack.py forge
    python wokwi_attack.py tamper
    python wokwi_attack.py replay
Depois confira: docker compose logs --tail 20 escola-wokwi-bridge
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

HMAC_FILE = Path(os.environ.get("HMAC_FILE", "/hmac/escola-nivel-01.json"))
BROKER = os.environ.get("PUBLIC_BROKER", "broker.hivemq.com")
PORT = int(os.environ.get("PUBLIC_PORT", "8883"))


def client() -> mqtt.Client:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"atacante-{secrets.token_hex(4)}")
    c.tls_set(cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    return c


def capture(topic: str, timeout: float = 30) -> bytes:
    got: dict[str, bytes] = {}
    done = threading.Event()
    c = client()
    c.on_connect = lambda cl, *_a: cl.subscribe(topic)

    def on_message(_c, _u, msg):
        got["payload"] = msg.payload
        done.set()

    c.on_message = on_message
    c.connect(BROKER, PORT)
    c.loop_start()
    print(f"[atacante] escutando {topic} (até {timeout:.0f}s; o ESP32 precisa estar rodando)...")
    if not done.wait(timeout):
        c.loop_stop()
        raise SystemExit("Nenhuma mensagem capturada. O ESP32 está rodando no Wokwi?")
    c.loop_stop()
    c.disconnect()
    print("[atacante] mensagem legítima capturada")
    return got["payload"]


def send(topic: str, payload: bytes) -> None:
    c = client()
    c.connect(BROKER, PORT)
    c.loop_start()
    c.publish(topic, payload).wait_for_publish(10)
    c.loop_stop()
    c.disconnect()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["forge", "tamper", "replay"])
    args = ap.parse_args()

    cfg = json.loads(HMAC_FILE.read_text())
    topic = f"{cfg['topic_prefix']}/escola/{cfg['device_id']}"   # só o tópico; a chave NÃO é usada

    if args.mode == "forge":
        body = json.dumps({
            "device_id": cfg["device_id"], "space": "escola", "sensor": "nivel_reservatorio",
            "value": 0.0, "unit": "%", "alarm_local": True, "boot_id": "deadbeef",
            "seq": 999999, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
        payload = json.dumps({"body": body, "sig": secrets.token_hex(32)}).encode()
        print("[atacante] enviando leitura FORJADA: nível 0 % com assinatura inventada")
    else:
        payload = capture(topic)
        if args.mode == "tamper":
            env = json.loads(payload)
            body = json.loads(env["body"])
            print(f"[atacante] alterando nível de {body['value']} % para 0.0 % (assinatura original mantida)")
            body["value"] = 0.0
            env["body"] = json.dumps(body)
            payload = json.dumps(env).encode()
        else:
            time.sleep(1)
            print("[atacante] reenviando a mesma mensagem (REPLAY)")

    send(topic, payload)
    print("[atacante] enviado. Veja a ponte: docker compose logs --tail 20 escola-wokwi-bridge")


if __name__ == "__main__":
    main()
