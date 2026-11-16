#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import ssl
import time
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

ap = argparse.ArgumentParser()
ap.add_argument("device")
ap.add_argument("sensor")
ap.add_argument("value", type=float)
ap.add_argument("unit")
args = ap.parse_args()

space = args.device.split("-", 1)[0]
broker = f"edge-{space}-broker"
certs = f"/pki/certs/{args.device}"
topic = f"va/{space}/telemetry/{args.device}"

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{args.device}-inject-{uuid.uuid4().hex[:4]}")
client.tls_set(ca_certs=f"{certs}/ca.crt", certfile=f"{certs}/{args.device}.crt",
               keyfile=f"{certs}/{args.device}.key", cert_reqs=ssl.CERT_REQUIRED,
               tls_version=ssl.PROTOCOL_TLS_CLIENT)
client.connect(broker, 8883)
client.loop_start()
msg = {"msg_id": str(uuid.uuid4()), "device_id": args.device, "space": space,
       "sensor": args.sensor, "value": args.value, "unit": args.unit,
       "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
client.publish(topic, json.dumps(msg), qos=1).wait_for_publish(5)
time.sleep(0.5)
client.loop_stop()
client.disconnect()
print(f"publicado em {broker}: {topic} = {args.value} {args.unit}")
