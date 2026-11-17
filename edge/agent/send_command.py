#!/usr/bin/env python3
"""
Ferramenta de manutenção da borda: envia um comando a um atuador do espaço
usando a identidade (certificado) do agente. Usada pelo SOAR para colocar
um atuador em modo seguro e, no laboratório, para simular um comando
indevido (regra (d) do SIEM).

    python send_command.py escola-bomba-01 safe_mode --by soar --minutes 30
    python send_command.py escola-bomba-01 off --by painel:ana.op --reason teste
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

SPACE = os.environ["SPACE"]
AGENT_ID = os.environ.get("AGENT_ID", f"edge-{SPACE}-agent")
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
BROKER = os.environ.get("BROKER_HOST", f"edge-{SPACE}-broker")

ap = argparse.ArgumentParser()
ap.add_argument("device")
ap.add_argument("action", choices=["on", "off", "safe_mode", "unlock", "deny"])
ap.add_argument("--by", default=AGENT_ID)
ap.add_argument("--reason", default="manual")
ap.add_argument("--minutes", type=int, default=30)
args = ap.parse_args()

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{AGENT_ID}-cmd-{uuid.uuid4().hex[:4]}")
client.tls_set(ca_certs=str(CERT_DIR / "ca.crt"), certfile=str(CERT_DIR / f"{AGENT_ID}.crt"),
               keyfile=str(CERT_DIR / f"{AGENT_ID}.key"), cert_reqs=ssl.CERT_REQUIRED,
               tls_version=ssl.PROTOCOL_TLS_CLIENT)
client.connect(BROKER, 8883)
client.loop_start()
payload = {"msg_id": str(uuid.uuid4()), "action": args.action, "by": args.by, "reason": args.reason,
           "minutes": args.minutes, "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
client.publish(f"va/{SPACE}/cmd/{args.device}", json.dumps(payload), qos=1).wait_for_publish(5)
time.sleep(0.3)
client.loop_stop()
client.disconnect()
print(f"comando enviado: {args.device} action={args.action} by={args.by}")
