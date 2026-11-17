#!/usr/bin/env python3
"""
Mini-SIEM da Rede Vila Aurora (RT-12, RT-13), sem dependências externas.

Coleta: segue os logs de TODOS os containers ('docker compose logs -f -t').
Todas as linhas levam o horário do daemon Docker (um único relógio, UTC),
o que dá uma linha do tempo consistente para a forense.
Armazenamento central: data/siem/siem.db (SQLite), retenção de 30 dias.

Regras de detecção (RT-13):
  (a) login/sessão VPN anômalo: credencial WireGuard de uma borda usada de
      outro host (IP diferente do agente dono) ou handshake em horário
      atípico (00h-05h, horário de Brasília)
  (b) padrão de SQL Injection nas buscas do painel
  (c) dispositivo sem certificado válido (sem certificado, CA falsa,
      revogado) no broker ou na ingestão, e mensagens forjadas na ponte do Wokwi
  (d) comando de atuador fora do perfil (emissor não autorizado) ou do horário

Cada alerta pede respostas ao SOAR (soar.py): baixo risco executa sozinho,
alto risco fica pendente de aprovação humana (RT-15).

Uso (na raiz do repositório, com o ambiente no ar):
    python siem/siem.py                    # monitora e responde
    python siem/siem.py --no-auto          # só alerta, não executa nada
    python siem/siem.py --since 30m        # reprocessa os últimos 30 min
    python siem/siem.py --input arquivo.log --dry-run   # teste offline
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soar  # noqa: E402

ROOT = soar.ROOT
RETENTION_DAYS = 30
DEDUP_SECONDS = 120
LOCAL_TZ = timezone(timedelta(hours=-3))
QUIET_HOURS = range(0, 5)        # 00h-04h59 (horário local); ajustável com --quiet-hours
ALLOWED_ISSUERS = {"soar"}       # além do agente da própria borda (edge-<espaco>-agent)

LINE_RE = re.compile(r"^(?P<svc>[\w.-]+)\s*\|\s(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z)\s(?P<msg>.*)$")
WG_RE = re.compile(r"peer=(\S+) allowed=(\S+) endpoint=(\S+) ultimo_handshake=(\d+)")
AUDIT_RE = re.compile(r'audit user=(\S+) role=(\S+) ip=(\S+) action=(\S+) result=(\S+) detail="(.*)"')
SQLI_RE = re.compile(r"('|--|;|/\*|\bunion\b|\bselect\b|\bdrop\b|\bsleep\s*\(|\bor\s+'?\w+'?\s*=\s*'?\w+)", re.I)
NEWCONN_RE = re.compile(r"New connection from ([\d.]+):\d+ on port")
TLS_FAIL_RE = re.compile(r"did not return a certificate|certificate verify failed|certificate revoked"
                         r"|unknown ca|bad certificate|tlsv1 alert", re.I)
INGEST_TLS_RE = re.compile(r"TLS RECUSADO ip=(\S+) motivo=(\S+)")
BRIDGE_RE = re.compile(r'REJEITADA motivo="([^"]+)"')
CMD_RE = re.compile(r"COMANDO RECEBIDO device=(\S+) action=(\S+) by=(\S+) reason=(\S+)")

RED, YEL, RST = "\033[91m", "\033[93m", "\033[0m"


class Context:
    """Informações do ambiente usadas pelas regras."""

    def __init__(self, offline: bool):
        self.offline = offline
        self.peer_name: dict[str, str] = {}        # chave pública -> agente
        self.vpn_ip_peer: dict[str, str] = {}      # 10.13.13.x -> chave pública
        self._ips: dict[str, tuple[str, str]] = {}
        self._ips_at = 0.0
        self.load_vpn()

    def load_vpn(self) -> None:
        keys_file = ROOT / "pki" / "out" / "wg" / "keys.json"
        inv = json.loads((ROOT / "pki" / "inventory.json").read_text(encoding="utf-8"))
        keys = json.loads(keys_file.read_text()) if keys_file.is_file() else {}
        for peer in inv.get("wireguard", {}).get("peers", []):
            pub = keys.get(peer["name"], {}).get("public")
            if pub:
                self.peer_name[pub] = peer["name"]
                self.vpn_ip_peer[peer["address"]] = pub

    def ips(self) -> dict[str, tuple[str, str]]:
        if self.offline:
            return self._ips
        if time.monotonic() - self._ips_at > 30:
            self._ips = soar.ip_map() or self._ips
            self._ips_at = time.monotonic()
        return self._ips

    def lookup(self, ip: str | None) -> tuple[str, str] | None:
        """IP -> (container, rede). Se não achar, atualiza o mapa na hora
        (o container suspeito pode ter acabado de ser criado)."""
        found = self.ips().get(ip or "")
        if found is None and not self.offline and time.monotonic() - self._ips_at > 3:
            self._ips_at = 0.0
            found = self.ips().get(ip or "")
        return found

    def container_ips(self, container: str) -> set[str]:
        return {ip for ip, (name, _) in self.ips().items() if name == container}


class Rules:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.last_conn_ip: dict[str, str] = {}
        self.last_handshake: dict[str, int] = {}

    def check(self, svc: str, ts: str, msg: str) -> list[dict]:
        alerts = []
        # ------------------------------------------------ (a) VPN anômala
        if svc == "cloud-wg" and (m := WG_RE.search(msg)):
            pub, allowed, endpoint, hs = m.group(1), m.group(2), m.group(3), int(m.group(4))
            name = self.ctx.peer_name.get(pub, f"par desconhecido {pub[:8]}")
            ip = endpoint.rsplit(":", 1)[0] if endpoint != "(none)" else None
            expected = self.ctx.container_ips(name)
            if ip and expected and ip not in expected:
                alerts.append(self.alert("a", "alta", f"Credencial VPN de {name} usada de outro host",
                                         f"endpoint {ip} nao pertence a {name} (esperado: {', '.join(sorted(expected))})",
                                         svc, msg, key=f"a:{pub}:{ip}",
                                         actions=[("encerrar_sessao_vpn", pub)] + self.isolate(ip)))
            new_hs = hs and hs != self.last_handshake.get(pub)
            self.last_handshake[pub] = hs
            if new_hs and datetime.fromtimestamp(hs, LOCAL_TZ).hour in QUIET_HOURS:
                alerts.append(self.alert("a", "media", f"Sessao VPN de {name} fora do horario",
                                         f"handshake as {datetime.fromtimestamp(hs, LOCAL_TZ):%H:%M} (horario local)",
                                         svc, msg, key=f"a-hora:{pub}", actions=[]))

        # ------------------------------------------------ (b) SQL Injection
        if svc == "painel":
            if (m := AUDIT_RE.search(msg)) and m.group(5) == "entrada_invalida" and SQLI_RE.search(m.group(6)):
                user = m.group(1)
                alerts.append(self.alert("b", "alta", f"Padrao de SQL Injection no painel (usuario {user})",
                                         f"busca rejeitada pela validacao: {m.group(6)[:120]}", svc, msg,
                                         key=f"b:{user}", actions=[("bloquear_usuario_painel", user)]))

        # ------------------------------------- (c) dispositivo sem certificado válido
        if svc.startswith("edge-") and svc.endswith("-broker"):
            if (m := NEWCONN_RE.search(msg)):
                self.last_conn_ip[svc] = m.group(1)
            elif (fail := TLS_FAIL_RE.search(msg)):
                ip = self.last_conn_ip.get(svc, "?")
                who = (self.ctx.lookup(ip) or ("desconhecido", ""))[0]
                alerts.append(self.alert("c", "alta", f"Conexao sem certificado valido no {svc}",
                                         f"origem {ip} ({who}): {fail.group(0)}", svc, msg,
                                         key=f"c:{svc}:{ip}", actions=self.isolate(ip)))
        if svc == "cloud-ingest" and (m := INGEST_TLS_RE.search(msg)):
            pub = self.ctx.vpn_ip_peer.get(m.group(1))
            alerts.append(self.alert("c", "alta", "Agente sem certificado valido tentou enviar dados a nuvem",
                                     f"ip VPN {m.group(1)} ({self.ctx.peer_name.get(pub, '?')}) motivo={m.group(2)}",
                                     svc, msg, key=f"c-ingest:{m.group(1)}",
                                     actions=[("encerrar_sessao_vpn", pub)] if pub else []))
        if svc == "escola-wokwi-bridge" and (m := BRIDGE_RE.search(msg)):
            alerts.append(self.alert("c", "media", "Mensagem forjada ou repetida para o ESP32 (trecho publico)",
                                     f"ponte rejeitou: {m.group(1)}", svc, msg, key="c-bridge",
                                     actions=[("rotacionar_chave_hmac", "escola-nivel-01")]))

        # --------------------------------------- (d) comando fora do perfil/horário
        if svc.startswith("field-") and (m := CMD_RE.search(msg)):
            device, action, by = m.group(1), m.group(2), m.group(3)
            space = device.split("-", 1)[0]
            agent = f"edge-{space}-agent"
            hour = datetime.fromisoformat(ts.replace("Z", "+00:00")[:19] + "+00:00").astimezone(LOCAL_TZ).hour
            not_allowed = by not in ALLOWED_ISSUERS | {agent}
            off_hours = by != agent and hour in QUIET_HOURS
            if not_allowed or off_hours:
                reason = f"emissor '{by}' nao autorizado" if not_allowed else f"comando manual as {hour}h"
                alerts.append(self.alert("d", "alta", f"Comando indevido para {device} ({action})",
                                         f"{reason}; so {agent} (regras locais) e o SOAR podem comandar atuadores",
                                         svc, msg, key=f"d:{device}:{by}",
                                         actions=[("modo_seguro_atuador", f"{space}:{device}"),
                                                  ("revogar_certificado", agent)]))
        return [a for a in alerts if a]

    def isolate(self, ip: str | None) -> list[tuple[str, str]]:
        container, network = self.ctx.lookup(ip) or (None, None)
        if not container or soar.is_protected(container):
            return []
        # o simulador de campo agrupa todos os sensores do espaço: isolar exige aprovação
        action = "isolar_campo_espaco" if container.startswith("field-") else "isolar_container"
        return [(action, f"{container}|{network}")]

    @staticmethod
    def alert(rule, severity, title, detail, svc, evidence, key, actions):
        return {"rule": rule, "severity": severity, "title": title, "detail": detail,
                "service": svc, "evidence": evidence, "key": key, "actions": actions}


class SIEM:
    def __init__(self, args):
        self.args = args
        self.conn = soar.connect()
        self.rules = Rules(Context(offline=bool(args.input)))
        self.recent: dict[str, float] = {}
        self.pending_logs: list[tuple] = []
        self.last_flush = time.monotonic()
        self.last_purge = 0.0
        self.alerts_file = soar.DB_PATH.parent / "alerts.jsonl"

    def purge(self) -> None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
        deleted = self.conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff,)).rowcount
        self.conn.commit()
        if deleted:
            print(f"[retencao] {deleted} linhas de log com mais de {RETENTION_DAYS} dias removidas")
        self.last_purge = time.monotonic()

    def flush(self) -> None:
        if self.pending_logs:
            self.conn.executemany("INSERT INTO logs (ts, service, line) VALUES (?, ?, ?)", self.pending_logs)
            self.conn.commit()
            self.pending_logs.clear()
        self.last_flush = time.monotonic()

    def handle(self, raw: str) -> None:
        m = LINE_RE.match(raw.rstrip("\n"))
        if not m:
            return
        svc, ts, msg = m.group("svc"), m.group("ts"), m.group("msg")
        self.pending_logs.append((ts, svc, msg))
        if len(self.pending_logs) >= 200 or time.monotonic() - self.last_flush > 1:
            self.flush()
        for alert in self.rules.check(svc, ts, msg):
            now = time.monotonic()
            if now - self.recent.get(alert["key"], -1e9) < DEDUP_SECONDS:
                continue
            self.recent[alert["key"]] = now
            self.raise_alert(alert, ts)

    def raise_alert(self, a: dict, ts: str) -> None:
        self.flush()
        cur = self.conn.execute(
            "INSERT INTO alerts (ts, rule, severity, title, detail, service, evidence, detected_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ts, a["rule"], a["severity"], a["title"], a["detail"], a["service"], a["evidence"], soar.utc_now()))
        self.conn.commit()
        alert_id = cur.lastrowid
        color = RED if a["severity"] == "alta" else YEL
        print(f"\n{color}[ALERTA {alert_id}] regra ({a['rule']}) severidade={a['severity'].upper()} {ts}{RST}")
        print(f"  {a['title']}\n  {a['detail']}\n  evidencia [{a['service']}]: {a['evidence'][:160]}")
        results = []
        for action, target in a["actions"]:
            status = soar.propose(self.conn, alert_id, action, target,
                                  auto=not self.args.no_auto, dry_run=self.args.dry_run)
            risk = soar.ACTIONS[action]["risco"]
            print(f"  -> SOAR {action} [{risk}] {target[:60]}: {status.upper()}"
                  + ("  (aprovar: python siem/soar.py pending)" if status == "pendente" else ""))
            results.append({"action": action, "target": target, "risk": risk, "status": status})
        with self.alerts_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": alert_id, "ts": ts, **{k: a[k] for k in
                     ("rule", "severity", "title", "detail", "service", "evidence")}, "acoes": results},
                     ensure_ascii=False) + "\n")

    def run(self) -> None:
        self.purge()
        if self.args.input:
            with open(self.args.input, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    self.handle(line)
            self.flush()
            return
        cmd = ["docker", "compose", "logs", "-f", "-t", "--no-color", "--since", self.args.since]
        print(f"SIEM Vila Aurora: coletando logs de todos os containers (desde {self.args.since}); "
              f"retencao {RETENTION_DAYS} dias; SOAR automatico {'DESLIGADO' if self.args.no_auto else 'LIGADO'}.")
        print("Ctrl+C para sair. Banco: data/siem/siem.db  Alertas: data/siem/alerts.jsonl\n")
        while True:
            proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace")
            try:
                for line in proc.stdout:
                    self.handle(line)
                    if time.monotonic() - self.last_purge > 3600:
                        self.purge()
            except KeyboardInterrupt:
                proc.terminate()
                self.flush()
                print("\nSIEM encerrado.")
                return
            self.flush()
            print("[coleta] fluxo de logs encerrado; reconectando em 3 s (o ambiente foi reiniciado?)")
            time.sleep(3)
            cmd[cmd.index("--since") + 1] = "10s"


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Mini-SIEM Vila Aurora")
    ap.add_argument("--since", default="1m", help="reprocessar logs desde (ex.: 30s, 10m, 1h)")
    ap.add_argument("--no-auto", action="store_true", help="não executar respostas automáticas")
    ap.add_argument("--dry-run", action="store_true", help="simular respostas (não chama o Docker)")
    ap.add_argument("--input", help="ler linhas de log de um arquivo (teste offline)")
    ap.add_argument("--quiet-hours", default="0-5",
                    help="horário atípico (local) para VPN e comandos, ex.: 0-5, 22-6 ou 'nenhum'")
    args = ap.parse_args()
    global QUIET_HOURS
    if args.quiet_hours == "nenhum":
        QUIET_HOURS = range(0)
    else:
        start, end = (int(x) for x in args.quiet_hours.split("-"))
        QUIET_HOURS = range(start, end) if start <= end else [*range(start, 24), *range(0, end)]
    if args.input:
        args.dry_run = True
    SIEM(args).run()


if __name__ == "__main__":
    main()
