#!/usr/bin/env python3
"""
Teste de caos controlado (RT-23): derruba os DOIS links WAN (fibra e 4G) de
uma borda por N minutos, mede o buffer e a recuperação, e religa sozinho.

    python metricas/caos.py --borda ubs --minutos 5 --injetar-alarme

Durante a queda: a borda entra em MODO DEGRADADO, as regras locais continuam
(com --injetar-alarme, a câmara fria vai a 12 °C e o alarme local dispara) e
os eventos se acumulam no buffer. Depois: reconexão e reconciliação.
Os números vão para docs/evidencias/caos_<data>.json (lidos pelo relatorio.py).
Se interromper com Ctrl+C, os links são religados mesmo assim.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "vila-aurora"
NETS = [f"{PROJECT}_seg-wan-fibra", f"{PROJECT}_seg-wan-4g"]
COUNT_SQL = ("import sqlite3; c = sqlite3.connect('/var/lib/agent/outbox.db'); "
             "print(c.execute('select count(*) from outbox where sent_at is null').fetchone()[0])")


def sh(cmd: list[str]) -> tuple[bool, str]:
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def pending(agent: str) -> int | None:
    ok, out = sh(["docker", "exec", agent, "python", "-c", COUNT_SQL])
    try:
        return int(out.splitlines()[-1]) if ok else None
    except (ValueError, IndexError):
        return None


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--borda", default="ubs", choices=["centro", "escola", "ubs", "horta", "abrigo"])
    ap.add_argument("--minutos", type=float, default=5)
    ap.add_argument("--injetar-alarme", action="store_true", help="câmara fria a 12 °C durante a queda (UBS)")
    args = ap.parse_args()
    agent = f"edge-{args.borda}-agent"
    record = {"borda": args.borda, "minutos_planejados": args.minutos, "buffer": []}

    before = pending(agent)
    print(f"[{now()}] buffer pendente antes da queda: {before}")
    record["inicio_utc"] = now()
    for net in NETS:
        ok, out = sh(["docker", "network", "disconnect", net, agent])
        print(f"[{now()}] link desconectado: {net} {'' if ok else '(' + out[-120:] + ')'}")
    t0 = time.monotonic()
    try:
        injected = False
        while (elapsed := time.monotonic() - t0) < args.minutos * 60:
            if args.injetar_alarme and not injected and elapsed > 45 and args.borda == "ubs":
                sh(["docker", "compose", "--profile", "tools", "run", "--rm", "--user", "root", "tools",
                    "python", "inject_reading.py", "ubs-camara-fria-01", "camara_fria", "12", "C"])
                print(f"[{now()}] câmara fria a 12 °C injetada (sem nuvem) -> veja o ALARME LOCAL no log da borda")
                injected = True
            p = pending(agent)
            record["buffer"].append({"t_s": round(elapsed), "pendentes": p})
            print(f"[{now()}] sem WAN há {elapsed/60:4.1f} min | eventos no buffer local: {p}")
            time.sleep(30)
    except KeyboardInterrupt:
        print("interrompido: religando os links...")
    finally:
        record["fim_queda_utc"] = now()
        record["minutos_sem_wan"] = round((time.monotonic() - t0) / 60, 2)
        for net in NETS:
            sh(["docker", "network", "connect", net, agent])
        print(f"[{now()}] links religados; aguardando a reconciliação...")

    t1 = time.monotonic()
    peak = max((b["pendentes"] or 0) for b in record["buffer"]) if record["buffer"] else 0
    while time.monotonic() - t1 < 180:
        p = pending(agent)
        if p is not None and p <= 5:
            break
        time.sleep(5)
    record["recuperacao_s"] = round(time.monotonic() - t1)
    record["buffer_pico"] = peak
    record["pendentes_apos"] = pending(agent)
    print(f"[{now()}] reconciliação: pico do buffer={peak}, pendentes agora={record['pendentes_apos']}, "
          f"tempo até esvaziar={record['recuperacao_s']} s")

    out = ROOT / "docs" / "evidencias" / f"caos_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Registro do teste: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
