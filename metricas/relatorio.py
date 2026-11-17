#!/usr/bin/env python3
"""
Relatório de métricas (RT-22) - Rede Vila Aurora.

    python metricas/relatorio.py --desde 120      # últimos 120 minutos

Calcula, a partir das fontes reais do laboratório:
  - disponibilidade (%): minutos com dados chegando na nuvem / minutos da janela,
    e minutos com a borda operando (logs do agente) / minutos da janela
  - tempo de operação autônoma: quedas da nuvem vistas por cada borda
  - perda de dados: eventos enviados pelo buffer da borda x gravados na nuvem
    (e duplicados, que devem ser 0)
  - MTTD: do evento (linha de log) até o alerta do SIEM
  - MTTR: do evento até a resposta executada (automática ou aprovada)
  - recursos da borda: CPU, memória e rede (docker stats)
  - energia: ESTIMADA (modelo de Raspberry Pi 4; não há hardware real)
  - último teste de caos (docs/evidencias/caos_*.json)

Saída: docs/evidencias/metricas_<data>.md e .json
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parent.parent
SIEM_DB = ROOT / "data" / "siem" / "siem.db"
SPACES = ["centro", "escola", "ubs", "horta", "abrigo"]
# modelo de energia (estimativa): Raspberry Pi 4, ~2,7 W ocioso e ~6,4 W com 4 núcleos em carga
P_IDLE_W, P_MAX_W, CORES = 2.7, 6.4, 4
COUNT_SQL = ("import sqlite3; c = sqlite3.connect('/var/lib/agent/outbox.db'); "
             "print(c.execute('select count(*) from outbox where sent_at is not null').fetchone()[0], "
             "c.execute('select count(*) from outbox where sent_at is null').fetchone()[0])")


def sh(cmd: list[str]) -> tuple[bool, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode == 0, p.stdout.strip()


def pg(sql: str) -> list[dict]:
    ok, out = sh(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "vilaaurora",
                  "-c", f"COPY ({sql}) TO STDOUT WITH CSV HEADER"])
    return list(csv.DictReader(io.StringIO(out))) if ok else []


def parse_ts(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    if "." in value:   # corta nanossegundos para microssegundos
        head, rest = value.split(".", 1)
        frac, tz = re.match(r"(\d+)(.*)", rest).groups()
        value = f"{head}.{frac[:6]}{tz}"
    return datetime.fromisoformat(value)


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--desde", type=int, default=120, help="janela em minutos")
    args = ap.parse_args()
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=args.desde)
    window_min = args.desde
    r: dict = {"janela_utc": [since.isoformat(timespec="seconds"), now.isoformat(timespec="seconds")]}

    # ---- disponibilidade da nuvem (dados chegando) por espaço
    rows = pg("SELECT space, count(DISTINCT date_trunc('minute', received_at)) AS minutos FROM events "
              f"WHERE received_at >= '{since.isoformat()}' GROUP BY space")
    cloud = {row["space"]: int(row["minutos"]) for row in rows}
    siem = sqlite3.connect(f"file:{SIEM_DB.as_posix()}?mode=ro", uri=True) if SIEM_DB.exists() else None
    since_s = since.isoformat().replace("+00:00", "Z")
    local = {}
    if siem:
        for s in SPACES:
            local[s] = siem.execute("SELECT count(DISTINCT substr(ts, 1, 16)) FROM logs WHERE service = ? AND ts >= ?",
                                    (f"edge-{s}-agent", since_s)).fetchone()[0]
    r["disponibilidade_pct"] = {s: {"dados_na_nuvem": round(100 * min(cloud.get(s, 0), window_min) / window_min, 1),
                                    "borda_operando": round(100 * min(local.get(s, 0), window_min) / window_min, 1)
                                    if siem else None} for s in SPACES}

    # ---- operação autônoma (quedas vistas pelos agentes)
    autonomy = {}
    if siem:
        for s in SPACES:
            secs = [float(m.group(1)) for (line,) in siem.execute(
                "SELECT line FROM logs WHERE service = ? AND ts >= ? AND line LIKE '%LINK RESTABELECIDO%'",
                (f"edge-{s}-agent", since_s)) if (m := re.search(r"apos (\d+)s", line))]
            autonomy[s] = {"quedas": len(secs), "total_s": int(sum(secs)), "maior_s": int(max(secs, default=0))}
    r["operacao_autonoma"] = autonomy

    # ---- perda de dados e duplicados
    db = {row["agent"]: (int(row["total"]), int(row["distintos"])) for row in
          pg("SELECT agent, count(*) AS total, count(DISTINCT msg_id) AS distintos FROM events GROUP BY agent")}
    loss = {}
    for s in SPACES:
        agent = f"edge-{s}-agent"
        ok, out = sh(["docker", "exec", agent, "python", "-c", COUNT_SQL])
        sent, pend = (int(x) for x in out.split()[-2:]) if ok and out else (None, None)
        total, distinct = db.get(agent, (0, 0))
        loss[s] = {"enviados_pela_borda": sent, "pendentes_no_buffer": pend, "gravados_na_nuvem": total,
                   "duplicados": total - distinct,
                   "perdidos": max(sent - total, 0) if sent is not None else None}
    r["dados"] = loss

    # ---- MTTD / MTTR
    mttd, mttr_auto, mttr_human = [], [], []
    if siem:
        for ts, det in siem.execute("SELECT ts, detected_at FROM alerts WHERE ts >= ? AND detected_at IS NOT NULL",
                                    (since_s,)):
            mttd.append((parse_ts(det) - parse_ts(ts)).total_seconds())
        for ts, decided_at, by in siem.execute(
                "SELECT al.ts, a.decided_at, a.decided_by FROM actions a JOIN alerts al ON al.id = a.alert_id "
                "WHERE al.ts >= ? AND a.status = 'executada' AND a.decided_at IS NOT NULL", (since_s,)):
            delta = (parse_ts(decided_at) - parse_ts(ts)).total_seconds()
            (mttr_auto if by == "automatico" else mttr_human).append(delta)
    fmt = lambda xs: {"n": len(xs), "media_s": round(mean(xs), 2) if xs else None}  # noqa: E731
    r["mttd"] = fmt(mttd)
    r["mttr_automatico"] = fmt(mttr_auto)
    r["mttr_com_aprovacao_humana"] = fmt(mttr_human)

    # ---- recursos da borda e energia estimada
    ok, out = sh(["docker", "stats", "--no-stream", "--format", "{{json .}}"])
    res = {}
    for line in out.splitlines() if ok else []:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if re.match(r"edge-(\w+)-(broker|agent)$", d.get("Name", "")):
            space = d["Name"].split("-")[1]
            cpu = float(d["CPUPerc"].rstrip("%") or 0)
            mem = d["MemUsage"].split("/")[0].strip()
            node = res.setdefault(space, {"cpu_pct": 0.0, "memoria": [], "rede": []})
            node["cpu_pct"] = round(node["cpu_pct"] + cpu, 2)
            node["memoria"].append(f"{d['Name'].split('-')[-1]}={mem}")
            node["rede"].append(f"{d['Name'].split('-')[-1]}={d['NetIO']}")
    for node in res.values():
        watts = P_IDLE_W + (P_MAX_W - P_IDLE_W) * min(node["cpu_pct"] / (100 * CORES), 1)
        node["energia_estimada_W"] = round(watts, 2)
        node["energia_estimada_Wh_dia"] = round(watts * 24, 1)
    r["recursos_borda"] = res

    # ---- último teste de caos
    chaos = sorted((ROOT / "docs" / "evidencias").glob("caos_*.json"))
    r["teste_caos"] = json.loads(chaos[-1].read_text(encoding="utf-8")) if chaos else None

    # ---- saída
    stamp = f"{now:%Y%m%dT%H%M%SZ}"
    out_dir = ROOT / "docs" / "evidencias"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"metricas_{stamp}.json").write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")

    md = [f"# Métricas — Rede Vila Aurora", "", f"Janela: {r['janela_utc'][0]} a {r['janela_utc'][1]} (UTC)", "",
          "## Disponibilidade e operação autônoma", "",
          "| Espaço | Dados na nuvem (%) | Borda operando (%) | Quedas | Tempo autônomo (s) | Maior queda (s) |",
          "|---|---|---|---|---|---|"]
    for s in SPACES:
        a, au = r["disponibilidade_pct"][s], autonomy.get(s, {})
        md.append(f"| {s} | {a['dados_na_nuvem']} | {a['borda_operando']} | {au.get('quedas', '-')} | "
                  f"{au.get('total_s', '-')} | {au.get('maior_s', '-')} |")
    md += ["", "## Integridade dos dados (buffer da borda × nuvem)", "",
           "| Espaço | Enviados pela borda | Pendentes no buffer | Gravados na nuvem | Duplicados | Perdidos |",
           "|---|---|---|---|---|---|"]
    md += [f"| {s} | {v['enviados_pela_borda']} | {v['pendentes_no_buffer']} | {v['gravados_na_nuvem']} | "
           f"{v['duplicados']} | {v['perdidos']} |" for s, v in loss.items()]
    md += ["", "## Detecção e resposta", "", "| Métrica | Ocorrências | Média (s) |", "|---|---|---|",
           f"| MTTD (evento → alerta) | {r['mttd']['n']} | {r['mttd']['media_s']} |",
           f"| MTTR automático (evento → resposta) | {r['mttr_automatico']['n']} | {r['mttr_automatico']['media_s']} |",
           f"| MTTR com aprovação humana | {r['mttr_com_aprovacao_humana']['n']} | "
           f"{r['mttr_com_aprovacao_humana']['media_s']} |",
           "", "## Recursos do nó de borda (broker + agente)", "",
           "| Espaço | CPU (%) | Memória | Rede (entrada/saída) | Energia estimada (W) | Wh/dia (estimado) |",
           "|---|---|---|---|---|---|"]
    md += [f"| {s} | {v['cpu_pct']} | {', '.join(v['memoria'])} | {', '.join(v['rede'])} | "
           f"{v['energia_estimada_W']} | {v['energia_estimada_Wh_dia']} |" for s, v in sorted(res.items())]
    md += ["", f"Energia **estimada** (sem hardware real): modelo de Raspberry Pi 4, "
               f"P = {P_IDLE_W} W + ({P_MAX_W} − {P_IDLE_W}) W × CPU/{CORES} núcleos."]
    if r["teste_caos"]:
        c = r["teste_caos"]
        md += ["", "## Teste de caos", "",
               f"Borda **{c['borda']}** sem fibra e sem 4G por **{c['minutos_sem_wan']} min** "
               f"({c['inicio_utc']} a {c['fim_queda_utc']}). Pico do buffer: {c['buffer_pico']} eventos; "
               f"reconciliação em {c['recuperacao_s']} s; pendentes após: {c['pendentes_apos']}."]
    (out_dir / f"metricas_{stamp}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print("\n".join(md))
    print(f"\nSalvo em docs/evidencias/metricas_{stamp}.md (e .json)")


if __name__ == "__main__":
    main()
