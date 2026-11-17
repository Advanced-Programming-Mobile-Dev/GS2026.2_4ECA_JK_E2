#!/usr/bin/env python3
"""
Gestão de usuários do painel (roda dentro do container):

    docker compose exec painel python manage.py create-user ana.coord coordenacao
    docker compose exec painel python manage.py list-users
    docker compose exec painel python manage.py reset-mfa ana.coord
    docker compose exec painel python manage.py set-role ana.coord auditor
    docker compose exec painel python manage.py lock-user ana.op 30     # usado pelo SOAR
    docker compose exec painel python manage.py unlock-user ana.op

Senhas: mínimo 12 caracteres, guardadas só como hash (scrypt, via werkzeug).
O MFA é cadastrado pelo próprio usuário no primeiro login (QR code).
"""
from __future__ import annotations

import argparse
import getpass
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

ROLES = ("operador", "tecnico", "coordenacao", "auditor")
USERS_DB = Path(os.environ.get("USERS_DB", "/data/painel.db"))


def connect() -> sqlite3.Connection:
    # reaproveita a criação das tabelas do app
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    os.environ.setdefault("PAINEL_SECRET_KEY", "cli")
    from app import init_users_db
    USERS_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(USERS_DB)
    conn.row_factory = sqlite3.Row
    init_users_db(conn)
    return conn


def ask_password() -> str:
    pw = os.environ.get("NEW_PASSWORD") or getpass.getpass("Senha (mín. 12 caracteres): ")
    if len(pw) < 12:
        sys.exit("Senha muito curta: use pelo menos 12 caracteres.")
    if not os.environ.get("NEW_PASSWORD") and pw != getpass.getpass("Repita a senha: "):
        sys.exit("As senhas não conferem.")
    return pw


def main() -> None:
    ap = argparse.ArgumentParser(description="Usuários do painel Vila Aurora")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-user"); p.add_argument("username"); p.add_argument("role", choices=ROLES)
    sub.add_parser("list-users")
    p = sub.add_parser("reset-mfa"); p.add_argument("username")
    p = sub.add_parser("set-role"); p.add_argument("username"); p.add_argument("role", choices=ROLES)
    p = sub.add_parser("lock-user"); p.add_argument("username"); p.add_argument("minutes", type=int, nargs="?", default=30)
    p = sub.add_parser("unlock-user"); p.add_argument("username")
    args = ap.parse_args()
    db = connect()

    if args.cmd == "create-user":
        if db.execute("SELECT 1 FROM users WHERE username = ?", (args.username,)).fetchone():
            sys.exit("Usuário já existe.")
        db.execute("INSERT INTO users (username, pw_hash, role) VALUES (?, ?, ?)",
                   (args.username.lower(), generate_password_hash(ask_password()), args.role))
        print(f"Usuário {args.username} criado com perfil {args.role}. O MFA será cadastrado no primeiro login.")
    elif args.cmd == "list-users":
        print(f"{'usuário':<20}{'perfil':<14}{'MFA':<6}bloqueado até")
        for r in db.execute("SELECT * FROM users ORDER BY username"):
            print(f"{r['username']:<20}{r['role']:<14}{'sim' if r['totp_enabled'] else 'não':<6}{r['locked_until'] or '-'}")
    elif args.cmd == "reset-mfa":
        db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last = 0 WHERE username = ?",
                   (args.username,))
        print("MFA zerado: o usuário cadastrará de novo no próximo login.")
    elif args.cmd == "set-role":
        db.execute("UPDATE users SET role = ? WHERE username = ?", (args.role, args.username))
        print(f"Perfil de {args.username} alterado para {args.role}.")
    elif args.cmd == "lock-user":
        until = (datetime.now(timezone.utc) + timedelta(minutes=args.minutes)).isoformat()
        cur = db.execute("UPDATE users SET locked_until = ? WHERE username = ?", (until, args.username))
        print(f"Usuário {args.username} bloqueado até {until}." if cur.rowcount else "Usuário não encontrado.")
    elif args.cmd == "unlock-user":
        db.execute("UPDATE users SET locked_until = NULL, failed = 0 WHERE username = ?", (args.username,))
        print(f"Usuário {args.username} desbloqueado.")
    db.commit()


if __name__ == "__main__":
    main()
