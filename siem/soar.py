#!/usr/bin/env python3
"""
SOAR da Rede Vila Aurora: respostas a incidentes classificadas por risco (RT-15).

  Risco BAIXO  -> executa sozinho (reversível, afeta um único elemento)
  Risco ALTO   -> fica PENDENTE até um humano aprovar

Uso (na raiz do repositório):
    python siem/soar.py list               # todas as ações
    python siem/soar.py pending            # ações aguardando aprovação
    python siem/soar.py approve <id>       # aprova e executa (registra quem aprovou)
    python siem/soar.py reject <id>
    python siem/soar.py restore <id>       # desfaz uma ação reversível
"""
from __future__ import annotations

import argparse
import getpass
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "siem" / "siem.db"
PROJECT = "vila-aurora"

# catálogo de ações e classificação de risco
ACTIONS = {
    "isolar_container":        {"risco": "baixo", "desc": "desconecta o container suspeito da rede em que foi visto"},
    "isolar_campo_espaco":     {"risco": "alto",  "desc": "desconecta o simulador de campo do espaço (todos os sensores dele)"},
    "encerrar_sessao_vpn":     {"risco": "baixo", "desc": "remove o par WireGuard na nuvem; a borda segue operando local"},
    "bloquear_usuario_painel": {"risco": "baixo", "desc": "bloqueia a conta no painel por 30 min e derruba a sessão"},
    "modo_seguro_atuador":     {"risco": "baixo", "desc": "atuador só aceita comandos do agente da borda por 30 min"},
    "revogar_certificado":     {"risco": "alto",  "desc": "revoga o certificado X.509; a identidade para até ser reemitida"},
    "rotacionar_chave_hmac":   {"risco": "alto",  "desc": "nova chave HMAC do ESP32; exige atualizar o main.py no Wokwi"},
}
# containers que nunca são isolados automaticamente (infraestrutura crítica)
PROTECTED_PREFIXES = ("edge-", "cloud-", "postgres", "painel")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ------------------------------------------------------------------- banco
def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, service TEXT NOT NULL, line TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
            title TEXT NOT NULL, detail TEXT, service TEXT, evidence TEXT);
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER, ts TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
            risk TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT,
            output TEXT, restore TEXT);
    """)
    # migração: horário real em que o SIEM gerou o alerta (para o MTTD)
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(alerts)")}
    if "detected_at" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN detected_at TEXT")
        conn.commit()
    return conn


# ------------------------------------------------------------------ docker
def run(cmd: list[str], interactive: bool = False) -> tuple[bool, str]:
    if interactive:
        proc = subprocess.run(cmd, cwd=ROOT)
        return proc.returncode == 0, f"exit={proc.returncode}"
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, out[-500:]


def docker_stdout(cmd: list[str]) -> str:
    """Só a saída padrão (o Docker Desktop no Windows escreve avisos no stderr)."""
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return proc.stdout.strip() if proc.returncode == 0 else ""


def ip_map() -> dict[str, tuple[str, str]]:
    """IP -> (container, rede) para todas as redes do projeto."""
    names = docker_stdout(["docker", "network", "ls", "--filter",
                           f"label=com.docker.compose.project={PROJECT}", "--format", "{{.Name}}"]).split()
    result: dict[str, tuple[str, str]] = {}
    for name in names:              # uma rede por vez: JSON simples e à prova de avisos extras
        out = docker_stdout(["docker", "network", "inspect", name, "--format", "{{json .Containers}}"])
        try:
            start = out.find("{")
            containers, _ = json.JSONDecoder().raw_decode(out[start:]) if start >= 0 else ({}, 0)
        except ValueError:
            continue
        for info in (containers or {}).values():
            ip = info.get("IPv4Address", "").split("/")[0]
            if ip:
                result[ip] = (info["Name"], name)
    return result


def is_protected(container: str) -> bool:
    return container.startswith(PROTECTED_PREFIXES)


# ---------------------------------------------------------------- execução
def execute(action: str, target: str, interactive: bool = False) -> tuple[bool, str, str | None]:
    """Executa a ação. Retorna (ok, saída, dado para desfazer)."""
    if action in ("isolar_container", "isolar_campo_espaco"):
        container, network = target.split("|", 1)
        ok, out = run(["docker", "network", "disconnect", network, container])
        return ok, out or f"{container} desconectado de {network}", target
    if action == "encerrar_sessao_vpn":
        ok, out = run(["docker", "exec", "cloud-wg", "wg", "set", "wg0", "peer", target, "remove"])
        return ok, out or "par removido do WireGuard da nuvem", target
    if action == "bloquear_usuario_painel":
        ok, out = run(["docker", "exec", "painel", "python", "manage.py", "lock-user", target, "30"])
        return ok, out, target
    if action == "modo_seguro_atuador":
        space, device = target.split(":", 1)
        ok, out = run(["docker", "exec", f"edge-{space}-agent", "python", "send_command.py",
                       device, "safe_mode", "--by", "soar", "--reason", "resposta_incidente", "--minutes", "30"])
        return ok, out, None
    if action == "revogar_certificado":
        ok, out = run([sys.executable, "pki/pki.py", "revoke", target, "--reason", "key_compromise"],
                      interactive=interactive)
        if ok:   # brokers e ingestão só releem a CRL ao reiniciar
            brokers = [f"edge-{s}-broker" for s in ("centro", "escola", "ubs", "horta", "abrigo")]
            ok, out2 = run(["docker", "compose", "restart", *brokers, "cloud-ingest"])
            out = f"{out}; reinicio: {out2[-200:]}"
        return ok, out, None
    if action == "rotacionar_chave_hmac":
        ok, out = run([sys.executable, "pki/pki.py", "hmac-rotate", target], interactive=interactive)
        if ok:
            ok, out2 = run(["docker", "compose", "restart", "escola-wokwi-bridge"])
            out = f"{out}; {out2[-200:]}"
        return ok, out, None
    return False, f"ação desconhecida: {action}", None


def propose(conn: sqlite3.Connection, alert_id: int, action: str, target: str,
            auto: bool = True, dry_run: bool = False) -> str:
    """Registra a ação; executa na hora se for de risco baixo (e auto ligado)."""
    risk = ACTIONS[action]["risco"]
    if risk == "baixo" and auto:
        if dry_run:
            ok, out, restore = True, "(simulação: nada executado)", None
        else:
            ok, out, restore = execute(action, target)
        status = "executada" if ok else "falhou"
        conn.execute("INSERT INTO actions (alert_id, ts, action, target, risk, status, decided_by, decided_at, output, restore)"
                     " VALUES (?, ?, ?, ?, ?, ?, 'automatico', ?, ?, ?)",
                     (alert_id, utc_now(), action, target, risk, status, utc_now(), out, restore))
    else:
        status = "pendente"
        conn.execute("INSERT INTO actions (alert_id, ts, action, target, risk, status) VALUES (?, ?, ?, ?, ?, ?)",
                     (alert_id, utc_now(), action, target, risk, status))
    conn.commit()
    return status


# --------------------------------------------------------------------- CLI
def show(rows) -> None:
    print(f"{'id':>4}  {'alerta':>6}  {'risco':<6} {'status':<10} {'ação':<24} alvo")
    for r in rows:
        target = r["target"] if len(r["target"]) < 50 else r["target"][:47] + "..."
        print(f"{r['id']:>4}  {r['alert_id'] or '-':>6}  {r['risk']:<6} {r['status']:<10} {r['action']:<24} {target}")


def main() -> None:
    ap = argparse.ArgumentParser(description="SOAR Vila Aurora")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("pending")
    for name in ("approve", "reject", "restore"):
        sub.add_parser(name).add_argument("id", type=int)
    args = ap.parse_args()
    conn = connect()

    if args.cmd in ("list", "pending"):
        where = "WHERE status = 'pendente'" if args.cmd == "pending" else ""
        show(conn.execute(f"SELECT * FROM actions {where} ORDER BY id"))
        return

    row = conn.execute("SELECT * FROM actions WHERE id = ?", (args.id,)).fetchone()
    if not row:
        sys.exit("Ação não encontrada.")
    who = getpass.getuser()

    if args.cmd in ("approve", "reject"):
        if row["status"] != "pendente":
            sys.exit(f"A ação {args.id} não está pendente (status: {row['status']}).")
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (row["alert_id"],)).fetchone()
        print(f"Alerta {alert['id']} ({alert['rule']}): {alert['title']}")
        print(f"Ação: {row['action']} -> {row['target']}  [risco {row['risk']}]")
        print(f"Efeito: {ACTIONS[row['action']]['desc']}")
        if args.cmd == "reject":
            conn.execute("UPDATE actions SET status='rejeitada', decided_by=?, decided_at=? WHERE id=?",
                         (who, utc_now(), args.id))
            conn.commit()
            print(f"Ação {args.id} REJEITADA por {who}.")
            return
        if input("Confirma a execução? Digite SIM: ").strip().upper() != "SIM":
            sys.exit("Cancelado.")
        ok, out, restore = execute(row["action"], row["target"], interactive=True)
        conn.execute("UPDATE actions SET status=?, decided_by=?, decided_at=?, output=?, restore=? WHERE id=?",
                     ("executada" if ok else "falhou", who, utc_now(), out, restore, args.id))
        conn.commit()
        print(f"Ação {args.id} APROVADA por {who} e {'executada' if ok else 'FALHOU'}: {out}")
        return

    # restore
    if row["status"] != "executada" or not row["restore"]:
        sys.exit("Esta ação não pode ser desfeita automaticamente.")
    if row["action"] in ("isolar_container", "isolar_campo_espaco"):
        container, network = row["restore"].split("|", 1)
        ok, out = run(["docker", "network", "connect", network, container])
    elif row["action"] == "encerrar_sessao_vpn":
        ok, out = run(["docker", "exec", "cloud-wg", "bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)"])
    elif row["action"] == "bloquear_usuario_painel":
        ok, out = run(["docker", "exec", "painel", "python", "manage.py", "unlock-user", row["restore"]])
    else:
        sys.exit("Esta ação não pode ser desfeita automaticamente.")
    conn.execute("UPDATE actions SET status=? WHERE id=?", ("desfeita" if ok else "falhou_desfazer", args.id))
    conn.commit()
    print(f"Ação {args.id} {'desfeita' if ok else 'NÃO desfeita'}: {out}")


if __name__ == "__main__":
    main()
