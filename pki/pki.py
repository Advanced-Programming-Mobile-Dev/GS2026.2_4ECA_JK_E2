#!/usr/bin/env python3
"""
PKI do projeto Rede Comunitária Vila Aurora.

CA própria do projeto, certificado X.509 único por dispositivo/serviço,
revogação via CRL e rotação de credenciais (RT-04, RT-05).

Uso:
    python pki/pki.py init                      # cria a CA (uma vez)
    python pki/pki.py issue-all                 # emite tudo que está em inventory.json
    python pki/pki.py issue <nome> --kind device|service|server [--san dns ...]
    python pki/pki.py revoke <nome> [--reason key_compromise]
    python pki/pki.py rotate <nome>             # revoga o atual e emite um novo
    python pki/pki.py list

A senha da chave da CA é lida da variável VA_CA_PASS ou pedida no terminal.
Tudo é gravado em pki/out/ (ignorado pelo git).
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
CA_DIR = OUT / "ca"
CERTS_DIR = OUT / "certs"
CRL_DIR = OUT / "crl"
INDEX_FILE = CA_DIR / "index.json"
INVENTORY_FILE = ROOT / "inventory.json"

ORG = "Rede Comunitaria Vila Aurora"
CA_VALID_DAYS = 5 * 365
LEAF_VALID_DAYS = 365
CRL_VALID_DAYS = 30
KINDS = ("device", "service", "server")

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
}


# ----------------------------------------------------------------- utilidades
def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def ca_passphrase(confirm: bool = False) -> bytes:
    value = os.environ.get("VA_CA_PASS")
    if value:
        return value.encode()
    value = getpass.getpass("Senha da chave da CA: ")
    if confirm and value != getpass.getpass("Confirme a senha: "):
        sys.exit("As senhas não conferem.")
    if len(value) < 8:
        sys.exit("Use uma senha com pelo menos 8 caracteres.")
    return value.encode()


def write_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, mode)


def load_index() -> dict:
    if not INDEX_FILE.exists():
        sys.exit("CA não encontrada. Rode primeiro: python pki/pki.py init")
    return json.loads(INDEX_FILE.read_text())


def save_index(index: dict) -> None:
    INDEX_FILE.write_text(json.dumps(index, indent=2, ensure_ascii=False))


def load_ca() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    cert = x509.load_pem_x509_certificate((CA_DIR / "ca.crt").read_bytes())
    key = serialization.load_pem_private_key(
        (CA_DIR / "ca.key").read_bytes(), password=ca_passphrase()
    )
    return cert, key


# ------------------------------------------------------------------------ CA
def cmd_init(_args) -> None:
    if (CA_DIR / "ca.key").exists():
        sys.exit("A CA já existe em pki/out/ca. Apague pki/out para recriar.")

    passphrase = ca_passphrase(confirm=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, "Vila Aurora Root CA"),
    ])
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    write_file(
        CA_DIR / "ca.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        ),
        0o600,
    )
    write_file(CA_DIR / "ca.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    save_index({"certs": {}})
    build_crl(cert, key, {"certs": {}})
    print(f"CA criada. Certificado: {CA_DIR / 'ca.crt'}")


def build_crl(ca_cert, ca_key, index: dict) -> None:
    now = utcnow()
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + dt.timedelta(days=CRL_VALID_DAYS))
    )
    for entry in index["certs"].values():
        for old in entry.get("history", []):
            if old["status"] != "revoked":
                continue
            revoked = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(old["serial"], 16))
                .revocation_date(dt.datetime.fromisoformat(old["revoked_at"]))
                .add_extension(x509.CRLReason(REASONS[old["reason"]]), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(ca_key, hashes.SHA256())
    write_file(CRL_DIR / "crl.pem", crl.public_bytes(serialization.Encoding.PEM), 0o644)
    print(f"CRL atualizada: {CRL_DIR / 'crl.pem'}")


# ------------------------------------------------------------------- emissão
def issue(name: str, kind: str, sans: list[str], ca_cert, ca_key, index: dict) -> None:
    if kind not in KINDS:
        sys.exit(f"Tipo inválido: {kind}. Use {KINDS}.")
    current = index["certs"].get(name)
    if current and current["history"][-1]["status"] == "valid":
        print(f"[pular] {name} já tem certificado válido (use 'rotate' para trocar).")
        return

    key = ec.generate_private_key(ec.SECP256R1())
    now = utcnow()
    serial = x509.random_serial_number()
    eku = ExtendedKeyUsageOID.SERVER_AUTH if kind == "server" else ExtendedKeyUsageOID.CLIENT_AUTH

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, kind),
            x509.NameAttribute(NameOID.COMMON_NAME, name),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=LEAF_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())

    folder = CERTS_DIR / name
    # Laboratório: a chave do broker precisa ser legível pelo usuário 'mosquitto'
    # dentro do container (UID 1883). Em produção: dono = mosquitto, modo 0600.
    key_mode = 0o644 if kind == "server" else 0o600
    write_file(
        folder / f"{name}.key",
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        key_mode,
    )
    write_file(folder / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM), 0o644)
    shutil.copy(CA_DIR / "ca.crt", folder / "ca.crt")

    entry = index["certs"].setdefault(name, {"kind": kind, "history": []})
    entry["kind"] = kind
    entry["sans"] = sans
    entry["history"].append({
        "serial": format(serial, "x"),
        "not_before": now.isoformat(),
        "not_after": (now + dt.timedelta(days=LEAF_VALID_DAYS)).isoformat(),
        "status": "valid",
    })
    print(f"[ok] {kind:<7} {name}  serial={format(serial, 'x')[:16]}…")


def cmd_issue(args) -> None:
    index = load_index()
    ca_cert, ca_key = load_ca()
    issue(args.name, args.kind, args.san or [], ca_cert, ca_key, index)
    save_index(index)


def cmd_issue_all(_args) -> None:
    index = load_index()
    ca_cert, ca_key = load_ca()
    inventory = json.loads(INVENTORY_FILE.read_text())
    for item in inventory["identities"]:
        issue(item["name"], item["kind"], item.get("sans", []), ca_cert, ca_key, index)
    save_index(index)


# --------------------------------------------------------- revogação/rotação
def revoke(name: str, reason: str, index: dict) -> None:
    entry = index["certs"].get(name)
    if not entry or entry["history"][-1]["status"] != "valid":
        sys.exit(f"{name} não tem certificado válido para revogar.")
    last = entry["history"][-1]
    last["status"] = "revoked"
    last["reason"] = reason
    last["revoked_at"] = utcnow().isoformat()
    print(f"[revogado] {name} serial={last['serial'][:16]}… motivo={reason}")


def cmd_revoke(args) -> None:
    index = load_index()
    ca_cert, ca_key = load_ca()
    revoke(args.name, args.reason, index)
    build_crl(ca_cert, ca_key, index)
    save_index(index)
    print("Reinicie o broker para recarregar a CRL: docker compose restart <broker>")


def cmd_rotate(args) -> None:
    index = load_index()
    ca_cert, ca_key = load_ca()
    entry = index["certs"].get(args.name)
    if not entry:
        sys.exit(f"{args.name} não existe no índice.")
    revoke(args.name, "superseded", index)
    issue(args.name, entry["kind"], entry.get("sans", []), ca_cert, ca_key, index)
    build_crl(ca_cert, ca_key, index)
    save_index(index)
    print("Reinicie o dispositivo e o broker para usar o novo certificado e a nova CRL.")


def cmd_list(_args) -> None:
    index = load_index()
    print(f"{'nome':<26}{'tipo':<9}{'status':<9}{'serial':<18}validade")
    for name, entry in sorted(index["certs"].items()):
        last = entry["history"][-1]
        print(f"{name:<26}{entry['kind']:<9}{last['status']:<9}"
              f"{last['serial'][:16]:<18}{last['not_after'][:10]}")


# ----------------------------------------------------------------------- CLI
def main() -> None:
    parser = argparse.ArgumentParser(description="PKI da Rede Vila Aurora")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="cria a CA do projeto").set_defaults(func=cmd_init)
    sub.add_parser("issue-all", help="emite o inventário").set_defaults(func=cmd_issue_all)
    sub.add_parser("list", help="lista certificados").set_defaults(func=cmd_list)

    p = sub.add_parser("issue", help="emite um certificado")
    p.add_argument("name")
    p.add_argument("--kind", choices=KINDS, required=True)
    p.add_argument("--san", nargs="*")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("revoke", help="revoga um certificado")
    p.add_argument("name")
    p.add_argument("--reason", choices=list(REASONS), default="key_compromise")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("rotate", help="rotaciona um certificado")
    p.add_argument("name")
    p.set_defaults(func=cmd_rotate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
