#!/usr/bin/env python3
"""
Coleta forense de um incidente (RT-14) - Rede Vila Aurora.

Exporta as evidências de uma janela de tempo, calcula o SHA-256 de cada
arquivo NO MOMENTO da coleta e registra a cadeia de custódia.

Fontes:
  - SIEM (data/siem/siem.db): logs de todos os containers, alertas e ações
  - Nuvem (PostgreSQL): eventos de telemetria, alarmes, comandos e acessos
  - CRL atual da PKI (certificados revogados)

Saída: docs/forense/<INCIDENTE>_<data>/
  logs.csv, alertas.csv, acoes_soar.csv, eventos_nuvem.csv, crl.pem,
  linha_do_tempo.csv, manifesto.json, cadeia_de_custodia.md

Uso (na raiz do repositório):
    python forense/coletar.py --incidente INC-VA-LAB-01 --desde 60
    python forense/coletar.py --verificar docs/forense/INC-VA-LAB-01_20261117T003000Z
"""
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import platform
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SIEM_DB = ROOT / "data" / "siem" / "siem.db"
CRL = ROOT / "pki" / "out" / "crl" / "crl.pem"

# linhas de log que entram na linha do tempo (fatos relevantes para o incidente)
KEY_EVENTS = re.compile(
    r"ALARME LOCAL|REGRA LOCAL|MODO DEGRADADO|LINK RESTABELECIDO|RECONCILIACAO concluida|WAN:|"
    r"COMANDO RECEBIDO|MODO SEGURO|COMANDO IGNORADO|REJEITADA|TLS RECUSADO|NEGADO|"
    r"did not return a certificate|certificate verify failed|result=(negado|falha|bloqueado|entrada_invalida|encerrada)|"
    r"lock-user|BOMBA", re.I)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path: Path, header: list[str], rows) -> int:
    n = 0
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow(r)
            n += 1
    return n


def export_postgres(path: Path, since: datetime) -> int:
    sql = ("COPY (SELECT msg_id, kind, space, device_id, sensor, value, unit, ts, received_at, agent, data "
           f"FROM events WHERE ts >= '{since.isoformat()}' ORDER BY ts) TO STDOUT WITH CSV HEADER")
    proc = subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres",
                           "-d", "vilaaurora", "-c", sql], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        print(f"[aviso] PostgreSQL indisponível: {proc.stderr.strip()[:200]}")
        path.write_text("indisponivel no momento da coleta\n", encoding="utf-8")
        return 0
    path.write_text(proc.stdout, encoding="utf-8")
    return max(proc.stdout.count("\n") - 1, 0)


def collect(args) -> None:
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=args.desde)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "docs" / "forense" / f"{args.incidente}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    if not SIEM_DB.exists():
        sys.exit("Banco do SIEM não encontrado (data/siem/siem.db). Rode o SIEM antes.")

    # leitura em modo somente leitura: a coleta não altera a fonte
    src = sqlite3.connect(f"file:{SIEM_DB.as_posix()}?mode=ro", uri=True)
    since_s = since.isoformat().replace("+00:00", "Z")
    counts = {}
    counts["logs.csv"] = write_csv(out / "logs.csv", ["ts_utc", "servico", "linha"],
                                   src.execute("SELECT ts, service, line FROM logs WHERE ts >= ? ORDER BY ts", (since_s,)))
    alerts = src.execute("SELECT id, ts, detected_at, rule, severity, title, detail, service, evidence "
                         "FROM alerts WHERE ts >= ? ORDER BY ts", (since_s,)).fetchall()
    counts["alertas.csv"] = write_csv(out / "alertas.csv", ["id", "ts_evento_utc", "detectado_em_utc", "regra",
                                      "severidade", "titulo", "detalhe", "servico", "evidencia"], alerts)
    actions = src.execute("SELECT a.id, a.alert_id, a.ts, a.action, a.target, a.risk, a.status, a.decided_by, "
                          "a.decided_at, a.output FROM actions a JOIN alerts al ON al.id = a.alert_id "
                          "WHERE al.ts >= ? ORDER BY a.id", (since_s,)).fetchall()
    counts["acoes_soar.csv"] = write_csv(out / "acoes_soar.csv", ["id", "alerta", "ts_utc", "acao", "alvo", "risco",
                                         "status", "decidido_por", "decidido_em", "saida"], actions)
    counts["eventos_nuvem.csv"] = export_postgres(out / "eventos_nuvem.csv", since)
    if CRL.is_file():
        shutil.copy2(CRL, out / "crl.pem")

    # linha do tempo consolidada: fatos dos logs + alertas + ações
    timeline = [(ts, "log", svc, line[:300]) for ts, svc, line in
                src.execute("SELECT ts, service, line FROM logs WHERE ts >= ? ORDER BY ts", (since_s,))
                if KEY_EVENTS.search(line)]
    timeline += [(a[1], f"ALERTA ({a[3]})", a[7], f"{a[5]} - {a[6]}") for a in alerts]
    timeline += [(a[2], f"SOAR {a[6]}", a[3], f"{a[4][:80]} risco={a[5]} por={a[7] or '-'}") for a in actions]
    timeline.sort(key=lambda r: r[0])
    counts["linha_do_tempo.csv"] = write_csv(out / "linha_do_tempo.csv",
                                             ["ts_utc", "tipo", "origem", "descricao"], timeline)
    src.close()

    # hashes + manifesto + cadeia de custódia
    files = sorted(p for p in out.iterdir() if p.is_file())
    manifest = {
        "incidente": args.incidente,
        "janela_utc": {"inicio": since.isoformat(), "fim": now.isoformat()},
        "coletado_por": args.responsavel,
        "coletado_em_utc": now.isoformat(),
        "estacao": f"{socket.gethostname()} ({platform.system()} {platform.release()})",
        "metodo": "exportacao somente-leitura do banco do SIEM (SQLite, mode=ro) e COPY do PostgreSQL; "
                  "SHA-256 calculado imediatamente apos a escrita de cada arquivo",
        "arquivos": [{"arquivo": p.name, "bytes": p.stat().st_size, "sha256": sha256(p),
                      "registros": counts.get(p.name)} for p in files],
    }
    (out / "manifesto.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    manifest_hash = sha256(out / "manifesto.json")

    lines = [f"# Cadeia de custódia — {args.incidente}", "",
             "| Campo | Valor |", "|---|---|",
             f"| Responsável pela coleta | {args.responsavel} |",
             f"| Data/hora da coleta (UTC) | {now.isoformat(timespec='seconds')} |",
             f"| Janela coletada (UTC) | {since.isoformat(timespec='seconds')} a {now.isoformat(timespec='seconds')} |",
             f"| Local / estação | {manifest['estacao']} |",
             f"| Método | {manifest['metodo']} |",
             f"| Hash do manifesto (SHA-256) | `{manifest_hash}` |", "",
             "## Arquivos coletados", "", "| Arquivo | Bytes | Registros | SHA-256 |", "|---|---|---|---|"]
    lines += [f"| {f['arquivo']} | {f['bytes']} | {f['registros'] if f['registros'] is not None else '-'} | `{f['sha256']}` |"
              for f in manifest["arquivos"]]
    lines += ["", "## Registro de transferências", "",
              "| Data/hora (UTC) | De | Para | Motivo | Hash do manifesto conferido? |", "|---|---|---|---|---|",
              f"| {now.isoformat(timespec='seconds')} | ambiente de laboratório | {args.responsavel} | coleta inicial | sim |",
              "| | | | | |", "",
              "Para verificar a integridade: `python forense/coletar.py --verificar <esta pasta>`"]
    (out / "cadeia_de_custodia.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Evidências em {out.relative_to(ROOT)}")
    for f in manifest["arquivos"]:
        print(f"  {f['sha256'][:16]}…  {f['arquivo']:<20} {f['registros'] if f['registros'] is not None else '':>6}")
    print(f"Hash do manifesto: {manifest_hash}")


def verify(folder: Path) -> None:
    manifest = json.loads((folder / "manifesto.json").read_text(encoding="utf-8"))
    ok = True
    for f in manifest["arquivos"]:
        actual = sha256(folder / f["arquivo"])
        good = actual == f["sha256"]
        ok &= good
        print(f"[{'OK' if good else 'ALTERADO'}] {f['arquivo']}")
    print("Integridade confirmada." if ok else "ATENÇÃO: evidência alterada após a coleta!")
    sys.exit(0 if ok else 1)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Coleta forense Vila Aurora")
    ap.add_argument("--incidente", default="INC-VA-LAB-01")
    ap.add_argument("--desde", type=int, default=60, help="minutos para trás a coletar (padrão 60)")
    ap.add_argument("--responsavel", default=getpass.getuser())
    ap.add_argument("--verificar", type=Path, help="pasta de uma coleta para conferir os hashes")
    args = ap.parse_args()
    if args.verificar:
        verify(args.verificar)
    else:
        collect(args)


if __name__ == "__main__":
    main()
