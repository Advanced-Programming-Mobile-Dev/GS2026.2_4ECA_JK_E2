#!/usr/bin/env python3
"""
Agente do nó de BORDA de um espaço comunitário (Rede Vila Aurora).

Funciona com ou sem internet (RT-01, RT-02, RT-03):

  1. Regras locais: lê a telemetria do broker local (mTLS) e decide na hora,
     sem depender da nuvem:
       - alarme da câmara fria fora de 2-8 °C (UBS);
       - alarme de alagamento acima de 10 cm (abrigo);
       - reservatório da escola: abaixo de 20 % liga a bomba (reabastecer),
         a partir de 95 % desliga (transbordo) - mesmo que o agendamento
         remoto tenha sido adulterado, como no INC-VA-0712;
       - acesso por crachá: libera ou nega pela lista sintética de crachás.
  2. Buffer store-and-forward (SQLite): todo evento é gravado antes de ser
     enviado; nada se perde quando o link cai.
  3. Uplink para a nuvem pelo túnel WireGuard, com HTTPS + mTLS. Se a nuvem
     não responde por FAILOVER_AFTER_S, troca o endpoint da VPN da fibra para
     o 4G; sem nenhum link, entra em MODO DEGRADADO e segue operando local.
     Ao voltar, reenvia o buffer (a nuvem descarta duplicados pelo msg_id).

Minimização (LGPD, RT-19): o UID do crachá nunca sai da borda; vai para a
nuvem só um pseudônimo HMAC-SHA256(pepper, uid).
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import logging
import os
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt
import requests

# ------------------------------------------------------------- configuração
SPACE = os.environ["SPACE"]
AGENT_ID = os.environ.get("AGENT_ID", f"edge-{SPACE}-agent")
BROKER_HOST = os.environ.get("BROKER_HOST", f"edge-{SPACE}-broker")
BROKER_PORT = int(os.environ.get("BROKER_PORT", "8883"))
CERT_DIR = Path(os.environ.get("CERT_DIR", "/certs"))
CLOUD_URL = os.environ.get("CLOUD_URL", "https://10.13.13.1:8443")
DB_PATH = Path(os.environ.get("DB_PATH", "/var/lib/agent/outbox.db"))
BADGES_FILE = Path(os.environ.get("BADGES_FILE", "/data/crachas.csv"))
BADGE_PEPPER = os.environ.get("BADGE_PEPPER", "")
WG_ENABLE = os.environ.get("WG_ENABLE", "1") == "1"
WG_IFACE = os.environ.get("WG_IFACE", "wg0")
WG_CONF = Path(os.environ.get("WG_CONF", "/etc/wireguard/wg0.conf"))
# links WAN em ordem de preferência: nome=host:porta
WAN_LINKS = [item.split("=", 1) for item in
             os.environ.get("WAN_LINKS", "fibra=cloud-fibra:51820,4g=cloud-4g:51820").split(",")]
FAILOVER_AFTER_S = float(os.environ.get("FAILOVER_AFTER_S", "30"))
PREFER_PRIMARY_S = float(os.environ.get("PREFER_PRIMARY_S", "120"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "200"))

CA = CERT_DIR / "ca.crt"
CLIENT_CERT = (str(CERT_DIR / f"{AGENT_ID}.crt"), str(CERT_DIR / f"{AGENT_ID}.key"))

# limites dos alarmes locais: sensor -> (mínimo, máximo); None = sem limite
ALARM_LIMITS = {
    "camara_fria": (2.0, 8.0),
    "alagamento": (None, 10.0),
    "nivel_reservatorio": (20.0, None),
}
PUMP_ID = "escola-bomba-01"
PUMP_ON_BELOW = 20.0     # % - reabastecer
PUMP_OFF_ABOVE = 95.0    # % - evitar transbordo

logging.Formatter.converter = time.gmtime
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)sZ %(levelname)s agent=" + AGENT_ID + " %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("agent")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_event(kind: str, **fields) -> dict:
    return {"msg_id": str(uuid.uuid4()), "kind": kind, "space": SPACE,
            "ts": utc_iso(), "origin": AGENT_ID, **fields}


# ------------------------------------------------------- buffer (outbox)
class Outbox:
    """Fila persistente: grava antes de enviar; marca como enviado só após o
    'ok' da nuvem. msg_id é chave primária, então reentregas MQTT (QoS 1)
    não duplicam."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS outbox (
                    msg_id     TEXT PRIMARY KEY,
                    kind       TEXT NOT NULL,
                    payload    TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    sent_at    TEXT
                )""")
            self.db.execute("CREATE INDEX IF NOT EXISTS idx_pending ON outbox(sent_at)")
            self.db.commit()

    def add(self, event: dict) -> None:
        with self.lock:
            self.db.execute(
                "INSERT OR IGNORE INTO outbox (msg_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                (event["msg_id"], event["kind"], json.dumps(event), utc_iso()))
            self.db.commit()

    def pending(self, limit: int) -> list[tuple[str, str]]:
        with self.lock:
            return self.db.execute(
                "SELECT msg_id, payload FROM outbox WHERE sent_at IS NULL ORDER BY rowid LIMIT ?",
                (limit,)).fetchall()

    def mark_sent(self, ids: list[str]) -> None:
        now = utc_iso()
        with self.lock:
            self.db.executemany("UPDATE outbox SET sent_at = ? WHERE msg_id = ?",
                                [(now, i) for i in ids])
            self.db.commit()

    def counts(self) -> tuple[int, int]:
        with self.lock:
            pending = self.db.execute("SELECT COUNT(*) FROM outbox WHERE sent_at IS NULL").fetchone()[0]
            sent = self.db.execute("SELECT COUNT(*) FROM outbox WHERE sent_at IS NOT NULL").fetchone()[0]
        return pending, sent


# --------------------------------------------------------- regras locais
class Rules:
    def __init__(self, publish, badges: dict[str, dict]):
        self.publish = publish           # publish(topic, dict)
        self.badges = badges
        self.alarm_active: dict[str, bool] = {}
        self.pump_state: str | None = None

    def handle(self, msg: dict) -> list[dict]:
        sensor = msg.get("sensor")
        if sensor == "rfid":
            return [self.access(msg)]
        events = [{**msg, "kind": "telemetry"}]
        if sensor == "bomba":
            self.pump_state = msg.get("state")
        elif isinstance(msg.get("value"), (int, float)):
            events += self.check_alarm(msg)
            if sensor == "nivel_reservatorio" and SPACE == "escola":
                events += self.control_pump(msg["value"])
        return events

    def check_alarm(self, msg: dict) -> list[dict]:
        limits = ALARM_LIMITS.get(msg["sensor"])
        if not limits:
            return []
        low, high = limits
        value, device = msg["value"], msg["device_id"]
        out = (low is not None and value < low) or (high is not None and value > high)
        if out == self.alarm_active.get(device, False):
            return []                     # só registra mudanças de estado
        self.alarm_active[device] = out
        event = new_event("alarm", device_id=device, sensor=msg["sensor"], value=value,
                          unit=msg.get("unit"), state="ATIVO" if out else "NORMALIZADO",
                          limits={"min": low, "max": high})
        self.publish(f"va/{SPACE}/alarm/{device}", event)
        if out:
            log.warning("ALARME LOCAL ATIVO sensor=%s device=%s valor=%s%s limites=%s "
                        "(sirene/sinal local acionado, sem depender da nuvem)",
                        msg["sensor"], device, value, msg.get("unit", ""), (low, high))
        else:
            log.info("alarme normalizado sensor=%s device=%s valor=%s", msg["sensor"], device, value)
        return [event]

    def control_pump(self, level: float) -> list[dict]:
        action, reason = None, None
        if level < PUMP_ON_BELOW and self.pump_state != "on":
            action, reason = "on", "nivel_baixo_reabastecer"
        elif level >= PUMP_OFF_ABOVE and self.pump_state != "off":
            action, reason = "off", "nivel_alto_evitar_transbordo"
        if not action:
            return []
        cmd = new_event("command", device_id=PUMP_ID, action=action, reason=reason,
                        by=AGENT_ID, trigger_level=level)
        self.publish(f"va/{SPACE}/cmd/{PUMP_ID}", cmd)
        self.pump_state = action
        log.warning("REGRA LOCAL: bomba %s (nivel=%.1f%%, motivo=%s)",
                    "LIGADA" if action == "on" else "DESLIGADA", level, reason)
        return [cmd]

    def access(self, msg: dict) -> dict:
        uid = str(msg.get("badge_uid", ""))
        badge = self.badges.get(uid)
        if badge is None:
            decision, reason = "negado", "cracha_desconhecido"
        elif badge["status"] != "ativo":
            decision, reason = "negado", "cracha_bloqueado"
        elif SPACE not in badge["espacos_autorizados"].split(";"):
            decision, reason = "negado", "sem_autorizacao_neste_espaco"
        else:
            decision, reason = "liberado", "ok"
        self.publish(f"va/{SPACE}/cmd/{msg['device_id']}",
                     {"action": "unlock" if decision == "liberado" else "deny",
                      "reason": reason, "by": AGENT_ID, "ts": utc_iso()})
        badge_hash = pseudonym(uid)
        log.info("ACESSO %s leitor=%s cracha=%s papel=%s motivo=%s", decision.upper(),
                 msg["device_id"], badge_hash[:8], badge["papel"] if badge else "-", reason)
        # o UID original NÃO segue para a nuvem
        return {"msg_id": msg["msg_id"], "kind": "access", "space": SPACE,
                "device_id": msg["device_id"], "sensor": "rfid", "ts": msg.get("ts", utc_iso()),
                "badge_hash": badge_hash, "papel": badge["papel"] if badge else None,
                "decision": decision, "reason": reason}


def pseudonym(uid: str) -> str:
    return hmac.new(BADGE_PEPPER.encode(), uid.encode(), hashlib.sha256).hexdigest()[:16]


def load_badges() -> dict[str, dict]:
    if not BADGES_FILE.exists():
        log.warning("sem lista de crachás (%s): todo acesso será negado", BADGES_FILE)
        return {}
    with BADGES_FILE.open(encoding="utf-8") as fh:
        return {row["badge_uid"]: row for row in csv.DictReader(fh)}


# ------------------------------------------------------ uplink e failover
class Uplink(threading.Thread):
    def __init__(self, outbox: Outbox):
        super().__init__(name="uplink", daemon=True)
        self.outbox = outbox
        self.session = requests.Session()
        # ignora variáveis de ambiente (proxy, REQUESTS_CA_BUNDLE): a nuvem só é
        # alcançada pelo túnel e só confiamos na CA do projeto
        self.session.trust_env = False
        self.session.cert = CLIENT_CERT
        self.session.verify = str(CA)
        self.link = 0                          # índice em WAN_LINKS
        now = time.monotonic()
        self.last_ok = now
        self.last_switch = now
        self.last_primary_try = now
        self.outage_started: float | None = None
        self.links_tried: set[int] = {0}
        self.degraded = False
        self.reconciling = False
        self.last_result: tuple[int, dict] | None = None
        self.sent_window = 0
        self.last_summary = now
        self.peer_pub = self._server_pubkey() if WG_ENABLE else None

    @staticmethod
    def _server_pubkey() -> str:
        in_peer = False
        for line in WG_CONF.read_text().splitlines():
            line = line.strip()
            if line == "[Peer]":
                in_peer = True
            elif in_peer and line.startswith("PublicKey"):
                return line.split("=", 1)[1].strip()
        raise SystemExit(f"PublicKey do servidor não encontrada em {WG_CONF}")

    @property
    def mode(self) -> str:
        return "degradado" if self.degraded else WAN_LINKS[self.link][0]

    # -- comunicação com a nuvem
    def send(self, batch: list[tuple[str, str]]) -> bool:
        try:
            resp = self.session.post(f"{CLOUD_URL}/ingest", timeout=5,
                                     json={"agent": AGENT_ID,
                                           "messages": [json.loads(p) for _, p in batch]})
            resp.raise_for_status()
            result = resp.json()
        except (requests.RequestException, ValueError) as exc:
            log.debug("envio falhou: %s", exc)
            return False
        self.outbox.mark_sent([i for i, _ in batch])
        self.sent_window += len(batch)
        self.last_result = (len(batch), result)
        return True

    def health(self) -> bool:
        try:
            return self.session.get(f"{CLOUD_URL}/health", timeout=3).ok
        except requests.RequestException:
            return False

    # -- troca de link da VPN
    def switch_to(self, idx: int, why: str) -> bool:
        name, endpoint = WAN_LINKS[idx]
        host, port = endpoint.rsplit(":", 1)
        try:
            ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except socket.gaierror:
            log.warning("WAN: link %s sem rota (%s não resolve)", name, host)
            return False
        if WG_ENABLE:
            subprocess.run(["wg", "set", WG_IFACE, "peer", self.peer_pub,
                            "endpoint", f"{ip}:{port}"], check=True)
        old = self.mode
        self.link = idx
        self.last_switch = time.monotonic()
        log.warning("WAN: %s -> %s (endpoint %s:%s) motivo=%s", old, name, ip, port, why)
        return True

    def failover(self) -> None:
        # todos os links já foram tentados e o atual também falhou: degradado
        if len(self.links_tried) >= len(WAN_LINKS) and not self.degraded:
            self.degraded = True
            pending, _ = self.outbox.counts()
            log.error("MODO DEGRADADO: nenhum link WAN responde; borda segue autonoma "
                      "(regras e alarmes locais ativos), eventos no buffer=%d", pending)
        for step in range(1, len(WAN_LINKS)):
            idx = (self.link + step) % len(WAN_LINKS)
            self.links_tried.add(idx)
            if self.switch_to(idx, f"nuvem sem resposta ha {time.monotonic() - self.last_ok:.0f}s"):
                break
        self.last_switch = time.monotonic()

    def on_success(self) -> None:
        now = time.monotonic()
        if self.outage_started is not None:
            pending, _ = self.outbox.counts()
            log.info("LINK RESTABELECIDO via %s apos %.0fs sem nuvem; reenviando o buffer (%d restantes)",
                     WAN_LINKS[self.link][0], now - self.outage_started, pending)
            self.outage_started = None
            self.reconciling = True
        if self.reconciling and self.last_result:
            size, result = self.last_result
            pending, _ = self.outbox.counts()
            log.info("RECONCILIACAO lote=%d novos=%d duplicados=%d restantes_no_buffer=%d",
                     size, result.get("inserted", 0), result.get("duplicates", 0), pending)
            if pending == 0:
                self.reconciling = False
                log.info("RECONCILIACAO concluida: buffer vazio, nenhum evento perdido")
        self.last_result = None
        self.degraded = False
        self.links_tried = {self.link}
        self.last_ok = now
        # volta para o link principal quando ele estiver disponível de novo
        if self.link != 0 and now - self.last_primary_try > PREFER_PRIMARY_S:
            self.last_primary_try = now
            self.switch_to(0, "link principal disponivel novamente")

    def run(self) -> None:
        log.info("uplink iniciado: nuvem=%s links=%s vpn=%s", CLOUD_URL,
                 [n for n, _ in WAN_LINKS], "wireguard" if WG_ENABLE else "desligada (teste)")
        while True:
            batch = self.outbox.pending(BATCH_SIZE)
            ok = self.send(batch) if batch else self.health()
            now = time.monotonic()
            if ok:
                self.on_success()
            else:
                if self.outage_started is None:
                    self.outage_started = now
                    log.warning("nuvem inacessivel via %s; eventos seguem para o buffer local",
                                WAN_LINKS[self.link][0])
                if now - self.last_ok > FAILOVER_AFTER_S and now - self.last_switch > FAILOVER_AFTER_S:
                    self.failover()
            if now - self.last_summary >= 60:
                pending, sent = self.outbox.counts()
                log.info("resumo modo=%s enviados_60s=%d pendentes=%d total_enviados=%d",
                         self.mode, self.sent_window, pending, sent)
                self.sent_window, self.last_summary = 0, now
            time.sleep(0.5 if (ok and batch) else 3)


# --------------------------------------------------------------------- main
def main() -> None:
    if not BADGE_PEPPER:
        raise SystemExit("Defina BADGE_PEPPER no .env (segredo da pseudonimização dos crachás).")
    outbox = Outbox(DB_PATH)
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=AGENT_ID)
    client.tls_set(ca_certs=str(CA), certfile=CLIENT_CERT[0], keyfile=CLIENT_CERT[1],
                   cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.reconnect_delay_set(1, 30)

    def publish(topic: str, payload: dict) -> None:
        client.publish(topic, json.dumps(payload), qos=1)

    rules = Rules(publish, load_badges())

    def on_connect(c, _u, _f, rc, _p):
        if rc.is_failure:
            log.error("broker local recusou: %s", rc)
            return
        c.subscribe(f"va/{SPACE}/telemetry/#", qos=1)
        log.info("conectado ao broker local %s (mTLS); regras locais ativas", BROKER_HOST)

    def on_message(_c, _u, msg):
        try:
            data = json.loads(msg.payload)
            if not isinstance(data, dict) or "msg_id" not in data or "device_id" not in data:
                raise ValueError("campos obrigatorios ausentes")
        except ValueError as exc:
            log.warning("mensagem invalida em %s ignorada: %s", msg.topic, exc)
            return
        for event in rules.handle(data):
            outbox.add(event)

    client.on_connect = on_connect
    client.on_message = on_message
    while True:
        try:
            client.connect(BROKER_HOST, BROKER_PORT, keepalive=30)
            break
        except (OSError, ssl.SSLError) as exc:
            log.error("broker local indisponivel (%s); nova tentativa em 5 s", exc)
            time.sleep(5)
    client.loop_start()
    Uplink(outbox).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
