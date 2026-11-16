#!/usr/bin/env python3
"""
Teste de evidência de mTLS e ACL no broker da borda (RT-04, RT-05).

Cenários (cada um tem um resultado ESPERADO; o teste passa quando o
comportamento real coincide com o esperado):

  T1  cliente sem certificado                    -> conexão recusada
  T2  certificado emitido por CA falsa           -> conexão recusada
  T3  certificado revogado (opcional, --revoked) -> conexão recusada
  T4  certificado válido da CA do projeto        -> conexão aceita
  T5  dispositivo publica na própria telemetria  -> mensagem entregue
  T6  dispositivo tenta publicar como outro      -> mensagem bloqueada (ACL)

Uso (dentro do container 'tools'):
    python mtls_check.py --broker edge-ubs-broker --space ubs
    python mtls_check.py --broker edge-ubs-broker --space ubs --revoked ubs-camara-fria-01

Gera um JSON de evidência em /evidencias (pasta docs/evidencias do repositório).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import uuid
from pathlib import Path

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERTS = Path(os.environ.get("PKI_CERTS", "/pki/certs"))
EVID = Path(os.environ.get("EVID_DIR", "/evidencias"))
TIMEOUT = 5.0


# ------------------------------------------------------------ utilidades
def ca_file(identity: str = "lab-tester-01") -> str:
    return str(CERTS / identity / "ca.crt")


def cert_pair(identity: str) -> tuple[str, str]:
    return str(CERTS / identity / f"{identity}.crt"), str(CERTS / identity / f"{identity}.key")


def make_rogue_cert(workdir: Path, cn: str) -> tuple[str, str]:
    """Cria uma CA falsa e um certificado de cliente assinado por ela."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA Falsa do Atacante")])
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    crt, key = workdir / "rogue.crt", workdir / "rogue.key"
    crt.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return str(crt), str(key)


def new_client(client_id: str, certfile: str | None, keyfile: str | None) -> mqtt.Client:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    client.tls_set(
        ca_certs=ca_file(),
        certfile=certfile,
        keyfile=keyfile,
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    return client


def try_connect(broker: str, port: int, client_id: str,
                certfile: str | None, keyfile: str | None) -> tuple[bool, str]:
    """Retorna (conectou?, detalhe)."""
    client = new_client(client_id, certfile, keyfile)
    done = threading.Event()
    result = {"ok": False, "detail": "sem resposta do broker (timeout)"}

    def on_connect(_c, _u, _f, reason_code, _p):
        result["ok"] = not reason_code.is_failure
        result["detail"] = f"CONNACK: {reason_code}"
        done.set()

    def on_disconnect(_c, _u, _f, reason_code, _p):
        if not done.is_set():
            result["detail"] = f"conexão encerrada pelo broker: {reason_code}"
            done.set()

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    try:
        client.connect(broker, port, keepalive=10)
    except (ssl.SSLError, OSError, socket.error) as exc:
        return False, f"handshake TLS falhou: {exc.__class__.__name__}: {exc}"
    client.loop_start()
    done.wait(TIMEOUT)
    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass
    return result["ok"], result["detail"]


def publish_and_observe(broker: str, port: int, space: str, publisher: str,
                        target_device: str) -> tuple[bool, str]:
    """Publica como 'publisher' no tópico de 'target_device' e verifica se o
    auditor (somente leitura em va/#) recebe a mensagem."""
    topic = f"va/{space}/telemetry/{target_device}"
    marker = str(uuid.uuid4())
    received = threading.Event()

    auditor = new_client(f"lab-auditor-{marker[:8]}", *cert_pair("lab-auditor"))
    subscribed = threading.Event()

    def on_connect(c, _u, _f, rc, _p):
        if not rc.is_failure:
            c.subscribe(topic, qos=1)

    def on_subscribe(_c, _u, _mid, _rcs, _p):
        subscribed.set()

    def on_message(_c, _u, msg):
        try:
            if json.loads(msg.payload).get("msg_id") == marker:
                received.set()
        except (ValueError, AttributeError):
            pass

    auditor.on_connect = on_connect
    auditor.on_subscribe = on_subscribe
    auditor.on_message = on_message
    auditor.connect(broker, port, keepalive=10)
    auditor.loop_start()
    subscribed.wait(TIMEOUT)

    pub = new_client(f"{publisher}", *cert_pair(publisher))
    pub.connect(broker, port, keepalive=10)
    pub.loop_start()
    time.sleep(0.5)
    payload = {"msg_id": marker, "device_id": publisher, "space": space,
               "sensor": "teste", "value": 0, "unit": "-",
               "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    pub.publish(topic, json.dumps(payload), qos=1).wait_for_publish(TIMEOUT)

    delivered = received.wait(TIMEOUT)
    for c in (pub, auditor):
        c.loop_stop()
        c.disconnect()
    detail = f"{publisher} -> {topic}: " + ("entregue ao assinante" if delivered
                                            else "descartada pelo broker (não entregue)")
    return delivered, detail


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------- main
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", default="edge-ubs-broker")
    ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--space", default="ubs")
    ap.add_argument("--victim", default="ubs-camara-fria-01",
                    help="dispositivo legítimo cujo tópico o testador tenta usar")
    ap.add_argument("--revoked", help="identidade já revogada, para o teste T3")
    args = ap.parse_args()

    results = []

    def record(test_id, description, expected_ok, ok, detail):
        passed = ok == expected_ok
        results.append({"id": test_id, "descricao": description,
                        "esperado": "aceito" if expected_ok else "recusado",
                        "obtido": "aceito" if ok else "recusado",
                        "passou": passed, "detalhe": detail})
        mark = "PASSOU" if passed else "FALHOU"
        print(f"[{mark}] {test_id} {description}\n         -> {detail}")

    with tempfile.TemporaryDirectory() as tmp:
        ok, d = try_connect(args.broker, args.port, "sem-cert", None, None)
        record("T1", "Cliente sem certificado", False, ok, d)

        rogue = make_rogue_cert(Path(tmp), args.victim)
        ok, d = try_connect(args.broker, args.port, "rogue", *rogue)
        record("T2", f"Certificado de CA falsa (CN={args.victim})", False, ok, d)

    if args.revoked:
        ok, d = try_connect(args.broker, args.port, f"{args.revoked}-test",
                            *cert_pair(args.revoked))
        record("T3", f"Certificado revogado ({args.revoked})", False, ok, d)

    ok, d = try_connect(args.broker, args.port, "lab-tester-01-conn", *cert_pair("lab-tester-01"))
    record("T4", "Certificado válido (lab-tester-01)", True, ok, d)

    ok, d = publish_and_observe(args.broker, args.port, args.space, "lab-tester-01", "lab-tester-01")
    record("T5", "Publicação no próprio tópico", True, ok, d)

    ok, d = publish_and_observe(args.broker, args.port, args.space, "lab-tester-01", args.victim)
    record("T6", f"Publicação se passando por {args.victim} (ACL)", False, ok, d)

    passed = sum(r["passou"] for r in results)
    print(f"\nResultado: {passed}/{len(results)} cenários com o comportamento esperado.")

    EVID.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = EVID / f"mtls_check_{stamp}.json"
    out.write_text(json.dumps({
        "teste": "mTLS e ACL do broker da borda",
        "broker": f"{args.broker}:{args.port}",
        "executado_em_utc": stamp,
        "resultados": results,
    }, indent=2, ensure_ascii=False))
    print(f"Evidência: docs/evidencias/{out.name}  sha256={sha256_of(out)}")


if __name__ == "__main__":
    main()
