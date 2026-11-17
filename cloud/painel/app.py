#!/usr/bin/env python3
"""
Painel de supervisão da Rede Vila Aurora (camada de supervisão).

Controles (RT-08, RT-09, RT-21):
  - Banco: usuário 'painel_reader' (só SELECT) e consultas SEMPRE
    parametrizadas; entradas validadas no servidor por lista branca/regex.
  - Erros genéricos para o usuário; detalhe só no log do servidor.
  - Login com senha (hash) + MFA TOTP obrigatório; bloqueio após 5 falhas.
  - RBAC com 4 perfis: operador, tecnico, coordenacao, auditor.
  - Sessão com cookie Secure/HttpOnly/SameSite=Strict, expiração de 30 min,
    token CSRF em todo formulário e cabeçalhos de segurança (CSP etc.).
  - Log de auditoria de cada ação (stdout para o SIEM + SQLite).
  - Acessibilidade WCAG 2.1 AA: HTML semântico, rótulos, contraste,
    navegação por teclado e status sempre em texto (não só cor).
"""
from __future__ import annotations

import functools
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pyotp
import segno
from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash

# ------------------------------------------------------------- configuração
DB_DSN = (f"host={os.environ.get('DB_HOST', 'postgres')} dbname={os.environ.get('DB_NAME', 'vilaaurora')} "
          f"user={os.environ.get('DB_USER', 'painel_reader')} password={os.environ.get('DB_PASSWORD', '')} "
          f"connect_timeout=3")
USERS_DB = Path(os.environ.get("USERS_DB", "/data/painel.db"))
ISSUER = "Rede Vila Aurora"

ROLES = ("operador", "tecnico", "coordenacao", "auditor")
# matriz de permissões (RBAC): permissão -> perfis que a possuem
PERMISSIONS = {
    "ver_painel":   {"operador", "tecnico", "coordenacao", "auditor"},
    "historico":    {"operador", "tecnico", "coordenacao", "auditor"},
    "dispositivos": {"tecnico", "coordenacao", "auditor"},
    "acessos":      {"coordenacao", "auditor"},
    "auditoria":    {"coordenacao", "auditor"},
}
SPACES = ("centro", "escola", "ubs", "horta", "abrigo")
KINDS = ("telemetry", "alarm", "command", "access")
DEVICE_RE = re.compile(r"^[a-z0-9-]{1,64}$")
USER_RE = re.compile(r"^[a-z0-9._-]{3,32}$")
MAX_FAILS, LOCK_MINUTES = 5, 5

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["PAINEL_SECRET_KEY"],
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)

logging.Formatter.converter = time.gmtime
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)sZ %(levelname)s service=painel %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger("painel")


# ------------------------------------------------- usuários e auditoria (SQLite)
def users_db() -> sqlite3.Connection:
    if "users_db" not in g:
        USERS_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(USERS_DB)
        conn.row_factory = sqlite3.Row
        init_users_db(conn)
        g.users_db = conn
    return g.users_db


def init_users_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
            username     TEXT PRIMARY KEY,
            pw_hash      TEXT NOT NULL,
            role         TEXT NOT NULL,
            totp_secret  TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_last    INTEGER NOT NULL DEFAULT 0,
            failed       INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT
        );
        CREATE TABLE IF NOT EXISTS audit (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT NOT NULL,
            username TEXT,
            role     TEXT,
            ip       TEXT,
            action   TEXT NOT NULL,
            detail   TEXT,
            result   TEXT NOT NULL
        );
    """)


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("users_db", None)
    if conn is not None:
        conn.close()


def audit(action: str, result: str, detail: str = "", username: str | None = None) -> None:
    user = username or session.get("user")
    role = session.get("role")
    ip = request.remote_addr
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db = users_db()
    db.execute("INSERT INTO audit (ts, username, role, ip, action, detail, result) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (now, user, role, ip, action, detail[:300], result))
    db.commit()
    level = logging.WARNING if result != "ok" else logging.INFO
    log.log(level, 'audit user=%s role=%s ip=%s action=%s result=%s detail="%s"',
            user, role, ip, action, result, detail[:300])


# ------------------------------------------------------------ banco de eventos
def query(sql: str, params: dict | tuple = ()) -> list[dict]:
    """Executa SEMPRE com parâmetros separados do SQL (nunca concatenação)."""
    with psycopg.connect(DB_DSN, row_factory=dict_row) as conn:
        return conn.execute(sql, params).fetchall()


# ------------------------------------------------------- segurança da sessão
@app.before_request
def security_checks():
    session.permanent = True
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        token = request.form.get("csrf", "")
        if not secrets.compare_digest(token, session["csrf"]):
            audit("csrf", "negado", request.path)
            abort(400)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                               "style-src 'self'; frame-ancestors 'none'; form-action 'self'")
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def template_globals():
    role = session.get("role")
    return {"csrf": session.get("csrf", ""), "user": session.get("user"), "role": role,
            "can": lambda perm: role in PERMISSIONS.get(perm, set())}


def requires(perm: str):
    def decorator(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if "user" not in session:
                return redirect(url_for("login"))
            # conta bloqueada (ex.: pelo SOAR) derruba a sessão na hora
            row = users_db().execute("SELECT locked_until FROM users WHERE username = ?",
                                     (session["user"],)).fetchone()
            if row is None or (row["locked_until"] and
                               datetime.fromisoformat(row["locked_until"]) > datetime.now(timezone.utc)):
                audit("sessao", "encerrada", "conta bloqueada")
                session.clear()
                return redirect(url_for("login"))
            if session.get("role") not in PERMISSIONS[perm]:
                audit(f"acesso:{perm}", "negado", request.path)
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------- erros
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(err):
    code = getattr(err, "code", 500)
    messages = {400: "Requisição inválida.", 403: "Você não tem permissão para acessar esta página.",
                404: "Página não encontrada.", 500: "Ocorreu um erro. Tente novamente mais tarde."}
    return render_template("erro.html", code=code, message=messages.get(code, messages[500])), code


@app.errorhandler(psycopg.Error)
def handle_db_error(err):
    # detalhe técnico só no log; o usuário vê mensagem genérica
    log.error("erro de banco: %s", err.__class__.__name__)
    return render_template("erro.html", code=503,
                           message="Os dados estão temporariamente indisponíveis."), 503


# ------------------------------------------------------------- autenticação
GENERIC_LOGIN_ERROR = "Usuário ou senha inválidos."


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    db = users_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() \
        if USER_RE.match(username) else None

    now = datetime.now(timezone.utc)
    if row and row["locked_until"] and datetime.fromisoformat(row["locked_until"]) > now:
        audit("login", "bloqueado", "conta temporariamente bloqueada", username)
        return render_template("login.html", error="Conta bloqueada temporariamente. Tente mais tarde."), 429

    if not row or not check_password_hash(row["pw_hash"], password):
        if row:
            fails = row["failed"] + 1
            locked = (now + timedelta(minutes=LOCK_MINUTES)).isoformat() if fails >= MAX_FAILS else None
            db.execute("UPDATE users SET failed = ?, locked_until = ? WHERE username = ?",
                       (0 if locked else fails, locked, username))
            db.commit()
        audit("login", "falha", "senha", username or "-")
        return render_template("login.html", error=GENERIC_LOGIN_ERROR), 401

    db.execute("UPDATE users SET failed = 0, locked_until = NULL WHERE username = ?", (username,))
    db.commit()
    session.clear()
    session["pending_user"] = username
    session["csrf"] = secrets.token_urlsafe(32)
    audit("login_senha", "ok", "", username)
    return redirect(url_for("mfa_setup" if not row["totp_enabled"] else "mfa"))


def pending_user() -> sqlite3.Row:
    username = session.get("pending_user")
    if not username:
        abort(403)
    return users_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def verify_totp(row: sqlite3.Row, secret: str, code: str) -> bool:
    """Valida o código e impede reutilizar o mesmo código (anti-replay)."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return False
    totp = pyotp.TOTP(secret)
    for offset in (-1, 0, 1):                       # tolera 30 s de diferença de relógio
        step = int(time.time() // 30) + offset
        if step > row["totp_last"] and secrets.compare_digest(totp.at(step * 30), code):
            users_db().execute("UPDATE users SET totp_last = ? WHERE username = ?", (step, row["username"]))
            users_db().commit()
            return True
    return False


def finish_login(row: sqlite3.Row):
    session.clear()
    session["user"], session["role"] = row["username"], row["role"]
    session["csrf"] = secrets.token_urlsafe(32)
    audit("login_mfa", "ok")
    return redirect(url_for("dashboard"))


@app.route("/mfa/configurar", methods=["GET", "POST"])
def mfa_setup():
    row = pending_user()
    if row["totp_enabled"]:
        return redirect(url_for("mfa"))
    secret = session.get("totp_setup") or pyotp.random_base32()
    session["totp_setup"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=row["username"], issuer_name=ISSUER)
    qr = segno.make(uri).svg_data_uri(scale=5)
    if request.method == "POST":
        if verify_totp(row, secret, request.form.get("code", "")):
            db = users_db()
            db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE username = ?",
                       (secret, row["username"]))
            db.commit()
            audit("mfa_cadastro", "ok", "", row["username"])
            return finish_login(row)
        audit("mfa_cadastro", "falha", "codigo invalido", row["username"])
        return render_template("mfa_setup.html", qr=qr, secret=secret, error="Código inválido."), 401
    return render_template("mfa_setup.html", qr=qr, secret=secret)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    row = pending_user()
    if request.method == "POST":
        if verify_totp(row, row["totp_secret"], request.form.get("code", "")):
            return finish_login(row)
        audit("login_mfa", "falha", "codigo invalido", row["username"])
        return render_template("mfa.html", error="Código inválido."), 401
    return render_template("mfa.html")


@app.route("/logout", methods=["POST"])
def logout():
    audit("logout", "ok")
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------ páginas
@app.route("/")
@requires("ver_painel")
def dashboard():
    latest = query("""
        SELECT DISTINCT ON (device_id) device_id, space, sensor, value, unit, ts
        FROM events
        WHERE kind = 'telemetry' AND value IS NOT NULL AND ts > now() - interval '1 hour'
        ORDER BY device_id, ts DESC""")
    alarms = query("""
        SELECT * FROM (
            SELECT DISTINCT ON (device_id) device_id, space, sensor, value, unit, ts,
                   data->>'state' AS state
            FROM events WHERE kind = 'alarm'
            ORDER BY device_id, ts DESC) last_alarm
        WHERE state = 'ATIVO' ORDER BY ts DESC""")
    audit("ver_painel", "ok")
    return render_template("dashboard.html", latest=latest, alarms=alarms)


@app.route("/historico")
@requires("historico")
def historico():
    """Busca no histórico: era o campo vulnerável do painel legado (INC-VA-0712).
    Agora: lista branca para espaço/tipo, regex para dispositivo, inteiro com
    limites para o período e SQL com parâmetros (%(nome)s) - a entrada do
    usuário nunca vira parte do texto SQL."""
    args = request.args
    errors = []
    space = args.get("space", "escola")
    if space not in SPACES:
        errors.append("Espaço inválido.")
    kind = args.get("kind", "telemetry")
    if kind not in KINDS:
        errors.append("Tipo de evento inválido.")
    device = args.get("device", "").strip()
    if device and not DEVICE_RE.match(device):
        errors.append("Dispositivo inválido: use só letras minúsculas, números e hífen.")
    try:
        hours = int(args.get("hours", "24"))
        if not 1 <= hours <= 168:
            raise ValueError
    except ValueError:
        errors.append("Período inválido: informe de 1 a 168 horas.")
        hours = 24

    rows = []
    if errors:
        audit("historico", "entrada_invalida", f"space={space} device={device} kind={kind} hours={args.get('hours', '')}")
    else:
        sql = """SELECT ts, space, device_id, sensor, value, unit, kind,
                        data->>'state' AS state, data->>'decision' AS decision
                 FROM events
                 WHERE space = %(space)s AND kind = %(kind)s
                   AND ts >= now() - make_interval(hours => %(hours)s)"""
        params = {"space": space, "kind": kind, "hours": hours}
        if device:
            sql += " AND device_id = %(device)s"
            params["device"] = device
        rows = query(sql + " ORDER BY ts DESC LIMIT 200", params)
        audit("historico", "ok", f"space={space} device={device or '*'} kind={kind} hours={hours}")
    return render_template("historico.html", rows=rows, errors=errors, spaces=SPACES, kinds=KINDS,
                           f={"space": space, "kind": kind, "device": device, "hours": hours})


@app.route("/dispositivos")
@requires("dispositivos")
def dispositivos():
    rows = query("""
        SELECT device_id, space, max(ts) AS last_ts,
               extract(epoch FROM now() - max(ts))::int AS seconds_ago
        FROM events WHERE kind IN ('telemetry', 'access')
        GROUP BY device_id, space ORDER BY space, device_id""")
    audit("dispositivos", "ok")
    return render_template("dispositivos.html", rows=rows)


@app.route("/acessos")
@requires("acessos")
def acessos():
    rows = query("""
        SELECT ts, space, device_id, data->>'badge_hash' AS badge, data->>'papel' AS papel,
               data->>'decision' AS decision, data->>'reason' AS reason
        FROM events WHERE kind = 'access' ORDER BY ts DESC LIMIT 100""")
    audit("acessos", "ok")
    return render_template("acessos.html", rows=rows)


@app.route("/auditoria")
@requires("auditoria")
def auditoria():
    rows = users_db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()
    audit("auditoria", "ok")
    return render_template("auditoria.html", rows=rows)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8443, ssl_context="adhoc")
