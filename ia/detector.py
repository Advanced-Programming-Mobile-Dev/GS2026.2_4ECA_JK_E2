#!/usr/bin/env python3
"""
IA defensiva (RT-16): detecção de anomalias na telemetria com Isolation Forest.

Por que Isolation Forest: não precisa de exemplos rotulados de ataque/falha
(raros na prática). A ideia: pontos anômalos são "isolados" com menos cortes
aleatórios. Numa árvore de isolamento, o comprimento médio do caminho h(x) é
menor para anomalias; o escore é  s(x) = 2^(-E[h(x)] / c(n)),  onde c(n) é o
caminho médio de uma busca malsucedida numa árvore binária com n pontos.
s próximo de 1 = anomalia; bem abaixo de 0,5 = normal.

Avaliação:
  1. exporta a telemetria real do PostgreSQL (dados sintéticos do laboratório);
  2. treina um modelo por tipo de sensor com 70% das leituras (as mais antigas);
  3. nos 30% restantes, injeta anomalias ROTULADAS (ex.: câmara fria a 12 °C,
     nível do reservatório despencando, turbidez disparando);
  4. mede precisão, revocação e taxa de falsos positivos.

Atributos por leitura: [valor, desvio em relação à mediana das 5 leituras
anteriores do mesmo dispositivo].

Uso (na raiz do repositório, com o ambiente no ar):
    pip install scikit-learn numpy
    python ia/detector.py
    python ia/detector.py --contaminacao 0.005 --anomalias 15
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parent.parent
SEED = 42


def load_telemetry() -> list[dict]:
    sql = ("COPY (SELECT device_id, sensor, value, ts FROM events WHERE kind = 'telemetry' "
           "AND value IS NOT NULL AND sensor NOT IN ('bomba') ORDER BY device_id, ts) TO STDOUT WITH CSV HEADER")
    proc = subprocess.run(["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres",
                           "-d", "vilaaurora", "-c", sql], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        sys.exit(f"Não consegui ler o PostgreSQL: {proc.stderr.strip()[:300]}")
    return list(csv.DictReader(io.StringIO(proc.stdout)))


def features(values: np.ndarray, window: int = 5) -> np.ndarray:
    """[valor, desvio em relação à mediana das 5 leituras anteriores].
    A mediana é robusta: depois de um pico isolado, a leitura seguinte (normal)
    não parece anômala."""
    dev = np.zeros(len(values))
    for i in range(1, len(values)):
        dev[i] = values[i] - np.median(values[max(0, i - window):i])
    return np.column_stack([values, dev])


def evaluate(rows: list[dict], contamination: float, n_anom: int, rng: np.random.Generator) -> dict:
    by_device: dict[tuple[str, str], list[float]] = defaultdict(list)
    for r in rows:
        by_device[(r["sensor"], r["device_id"])].append(float(r["value"]))

    by_sensor: dict[str, list[np.ndarray]] = defaultdict(list)
    for (sensor, _), vals in by_device.items():
        by_sensor[sensor].append(np.array(vals))

    results = {}
    total = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for sensor, series in sorted(by_sensor.items()):
        train_parts, test_parts = [], []
        for s in series:
            if len(s) < 30:
                continue
            cut = int(len(s) * 0.7)
            train_parts.append(features(s[:cut]))
            test_parts.append(s[cut:])
        if not train_parts:
            continue
        X_train = np.vstack(train_parts)
        mu, sd = X_train[:, 0].mean(), max(X_train[:, 0].std(), 1e-3)

        # teste: leituras normais + anomalias injetadas (rótulo 1)
        X_test, y_test = [], []
        for s in test_parts:
            vals = s.copy()
            labels = np.zeros(len(vals), dtype=int)
            k = max(1, n_anom // len(test_parts))
            idx = rng.choice(np.arange(1, len(vals)), size=min(k, len(vals) - 1), replace=False)
            for i in idx:
                # desvio de 6 a 12 desvios-padrão (ex.: câmara fria 5 °C -> ~12 °C)
                vals[i] = mu + rng.choice([-1, 1]) * rng.uniform(6, 12) * sd
                labels[i] = 1
            X_test.append(features(vals))
            y_test.append(labels)
        X_test, y_test = np.vstack(X_test), np.concatenate(y_test)

        model = IsolationForest(n_estimators=200, contamination=contamination, random_state=SEED)
        model.fit(X_train)
        pred = (model.predict(X_test) == -1).astype(int)    # -1 = anomalia

        tp = int(((pred == 1) & (y_test == 1)).sum())
        fp = int(((pred == 1) & (y_test == 0)).sum())
        fn = int(((pred == 0) & (y_test == 1)).sum())
        tn = int(((pred == 0) & (y_test == 0)).sum())
        for k_, v in zip(("tp", "fp", "fn", "tn"), (tp, fp, fn, tn)):
            total[k_] += v
        results[sensor] = metrics(tp, fp, fn, tn) | {"treino": len(X_train), "teste": len(X_test)}
    results["TOTAL"] = metrics(**total)
    return results


def metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precisao": round(precision, 3), "revocacao": round(recall, 3), "taxa_falso_positivo": round(fpr, 4)}


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Isolation Forest na telemetria da Rede Vila Aurora")
    ap.add_argument("--contaminacao", type=float, default=0.01,
                    help="fração esperada de anomalias (limiar do modelo)")
    ap.add_argument("--anomalias", type=int, default=15, help="anomalias injetadas por tipo de sensor")
    ap.add_argument("--csv", type=Path, help="usar um CSV exportado (device_id,sensor,value,ts) em vez do banco")
    args = ap.parse_args()

    if args.csv:
        rows = list(csv.DictReader(args.csv.open(encoding="utf-8")))
    else:
        rows = load_telemetry()
    print(f"{len(rows)} leituras de telemetria carregadas")
    res = evaluate(rows, args.contaminacao, args.anomalias, np.random.default_rng(SEED))

    print(f"\n{'sensor':<20}{'treino':>7}{'teste':>7}{'VP':>5}{'FP':>5}{'FN':>5}"
          f"{'precisão':>10}{'revocação':>11}{'tx FP':>8}")
    for sensor, m in res.items():
        print(f"{sensor:<20}{m.get('treino', ''):>7}{m.get('teste', ''):>7}{m['tp']:>5}{m['fp']:>5}{m['fn']:>5}"
              f"{m['precisao']:>10.3f}{m['revocacao']:>11.3f}{m['taxa_falso_positivo']:>8.4f}")

    out = ROOT / "docs" / "evidencias" / f"ia_isolation_forest_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"modelo": "IsolationForest", "n_estimators": 200,
                               "contaminacao": args.contaminacao, "anomalias_injetadas_por_sensor": args.anomalias,
                               "atributos": ["valor", "desvio_vs_mediana_5_anteriores"],
                               "resultados": res}, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nResultados salvos em {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
