#!/usr/bin/env python3
"""
Gera os dados SINTÉTICOS da Rede Vila Aurora (RT-19): pessoas fictícias,
papéis e crachás RFID. Nenhum dado pessoal real é usado.

A seed é fixa, então o resultado é sempre o mesmo (reprodutível).

Uso:
    python data/generate_synthetic.py            # grava em data/synthetic/
    python data/generate_synthetic.py --seed 7 --pessoas 300
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

OUT = Path(__file__).resolve().parent / "synthetic"

ESPACOS = ["centro", "escola", "ubs", "horta", "abrigo"]

# Papéis e acesso. Moradores só entram no abrigo e no centro; equipes entram onde atuam.
PAPEIS = [
    # papel,        peso, espaços autorizados
    ("morador",      60, ["centro", "abrigo"]),
    ("voluntario",   25, ["centro", "horta", "abrigo"]),
    ("operador",      6, ["centro", "escola", "horta", "abrigo"]),
    ("tecnico",       4, ESPACOS),
    ("coordenacao",   3, ESPACOS),
    ("saude",         2, ["ubs", "abrigo"]),
]

NOMES = ["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fábio", "Gabriela", "Heitor",
         "Isabela", "João", "Karina", "Lucas", "Marina", "Nicolas", "Olívia", "Paulo",
         "Rafaela", "Samuel", "Tatiana", "Vítor", "Yasmin", "Wesley", "Luana", "Caio"]
SOBRENOMES = ["Silva", "Souza", "Oliveira", "Pereira", "Lima", "Costa", "Ferreira",
              "Almeida", "Ribeiro", "Carvalho", "Gomes", "Martins", "Rocha", "Barbosa"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--pessoas", type=int, default=200)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    OUT.mkdir(parents=True, exist_ok=True)

    pessoas, crachas = [], []
    pesos = [p[1] for p in PAPEIS]
    used_uids: set[str] = set()

    for i in range(1, args.pessoas + 1):
        papel, _, espacos = rng.choices(PAPEIS, weights=pesos, k=1)[0]
        pessoa_id = f"P{i:04d}"
        pessoas.append({
            "pessoa_id": pessoa_id,
            "nome": f"{rng.choice(NOMES)} {rng.choice(SOBRENOMES)} (fictício)",
            "papel": papel,
            # telefone obviamente fictício (prefixo 0000)
            "telefone": f"(00) 0000-{rng.randint(0, 9999):04d}",
        })
        uid = None
        while uid is None or uid in used_uids:
            uid = "".join(rng.choice("0123456789ABCDEF") for _ in range(8))
        used_uids.add(uid)
        crachas.append({
            "badge_uid": uid,
            "pessoa_id": pessoa_id,
            "papel": papel,
            "espacos_autorizados": ";".join(espacos),
            # ~5% dos crachás bloqueados (perdidos ou desligados)
            "status": "bloqueado" if rng.random() < 0.05 else "ativo",
        })

    write_csv(OUT / "pessoas.csv", pessoas)
    write_csv(OUT / "crachas.csv", crachas)

    ativos = sum(c["status"] == "ativo" for c in crachas)
    print(f"{len(pessoas)} pessoas e {len(crachas)} crachás ({ativos} ativos) em {OUT}")


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
