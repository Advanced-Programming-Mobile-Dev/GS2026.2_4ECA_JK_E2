#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import getpass
import json
import os
import secrets
import shutil
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"
CA_DIR = OUT / "ca"
CERTS_DIR = OUT / "certs"
CRL_DIR = OUT / "crl"
INDEX_FILE = CA_DIR / "index.json"
HMAC_DIR = OUT / "hmac"
WG_DIR = OUT / "wg"
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


def remove_docker_artifact(path: Path) -> None:
    """Se o docker compose subir antes da PKI, o Docker cria PASTAS vazias no
    lugar dos arquivos montados (ex.: uma pasta chamada 'ca.crt'). Remove essas
    pastas para o arquivo verdadeiro poder ser gravado."""
    if path.is_dir():
        shutil.rmtree(path)
        print(f"[corrigido] {path} era uma pasta criada pelo Docker; removida.")


def write_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    remove_docker_artifact(path)
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
def san_entry(value: str) -> x509.GeneralName:
    """SAN de IP (ex.: 10.13.13.1, endereço da nuvem na VPN) ou de nome DNS."""
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def issue(name: str, kind: str, sans: list[str], ca_cert, ca_key, index: dict) -> None:
    if kind not in KINDS:
        sys.exit(f"Tipo inválido: {kind}. Use {KINDS}.")
    current = index["certs"].get(name)
    folder = CERTS_DIR / name
    files_ok = all((folder / f).is_file() for f in (f"{name}.crt", f"{name}.key", "ca.crt"))
    if current and current["history"][-1]["status"] == "valid":
        if files_ok:
            print(f"[pular] {name} já tem certificado válido (use 'rotate' para trocar).")
            return
        # arquivos ausentes ou substituídos por pastas do Docker: reemitir
        current["history"][-1]["status"] = "lost"
        print(f"[reemitir] {name}: arquivos do certificado ausentes ou inválidos.")

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
            x509.SubjectAlternativeName([san_entry(s) for s in sans]), critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256())

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
    remove_docker_artifact(folder / "ca.crt")
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
    inventory = json.loads(INVENTORY_FILE.read_text(encoding="utf-8"))
    for item in inventory["identities"]:
        issue(item["name"], item["kind"], item.get("sans", []), ca_cert, ca_key, index)
    save_index(index)
    for item in inventory.get("hmac_devices", []):
        hmac_path = HMAC_DIR / f"{item['name']}.json"
        remove_docker_artifact(hmac_path)
        if hmac_path.is_file():
            print(f"[pular] {item['name']} já tem chave HMAC (use 'hmac-rotate' para trocar).")
        else:
            make_hmac(item["name"])
    if "wireguard" in inventory:
        make_wireguard(inventory["wireguard"])


# ------------------------------------------------------------------ WireGuard
# Chaves Curve25519 (X25519) da VPN borda <-> nuvem (RT-06). Cada borda só
# tem rota para o IP da nuvem (AllowedIPs /32): as bordas não se enxergam.
# PresharedKey por par: camada simétrica extra (resistência pós-quântica).
def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def wg_keypair() -> dict:
    key = x25519.X25519PrivateKey.generate()
    return {
        "private": b64(key.private_bytes(serialization.Encoding.Raw,
                                         serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption())),
        "public": b64(key.public_key().public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw)),
    }


def make_wireguard(cfg: dict) -> None:
    keys_file = WG_DIR / "keys.json"
    remove_docker_artifact(keys_file)
    keys = json.loads(keys_file.read_text()) if keys_file.is_file() else {}
    server, peers = cfg["server"], cfg["peers"]
    created = []
    for name in [server["name"]] + [p["name"] for p in peers]:
        if name not in keys:
            keys[name] = wg_keypair()
            created.append(name)
    for p in peers:
        psk_name = f"psk:{p['name']}"
        if psk_name not in keys:
            keys[psk_name] = {"psk": b64(secrets.token_bytes(32))}
    write_file(keys_file, json.dumps(keys, indent=2).encode(), 0o600)

    # configuração da nuvem: um [Peer] por borda
    lines = ["# Gerado por pki.py - VPN WireGuard da Rede Vila Aurora (nuvem)",
             "[Interface]",
             f"Address = {server['address']}/24",
             f"ListenPort = {server['port']}",
             f"PrivateKey = {keys[server['name']]['private']}", ""]
    for p in peers:
        lines += [f"# {p['name']}", "[Peer]",
                  f"PublicKey = {keys[p['name']]['public']}",
                  f"PresharedKey = {keys['psk:' + p['name']]['psk']}",
                  f"AllowedIPs = {p['address']}/32", ""]
    write_file(WG_DIR / f"{server['name']}.conf", "\n".join(lines).encode(), 0o600)

    # configuração de cada borda: só alcança o IP da nuvem
    primary = server["endpoints"][0]
    for p in peers:
        lines = [f"# Gerado por pki.py - VPN WireGuard ({p['name']})",
                 "[Interface]",
                 f"Address = {p['address']}/32",
                 f"PrivateKey = {keys[p['name']]['private']}", "",
                 "[Peer]",
                 f"PublicKey = {keys[server['name']]['public']}",
                 f"PresharedKey = {keys['psk:' + p['name']]['psk']}",
                 f"Endpoint = {primary}:{server['port']}",
                 f"AllowedIPs = {server['address']}/32",
                 "PersistentKeepalive = 15", ""]
        write_file(WG_DIR / f"{p['name']}.conf", "\n".join(lines).encode(), 0o600)
    print(f"[ok] wireguard {len(peers)} bordas + nuvem"
          + (f" (chaves novas: {', '.join(created)})" if created else " (chaves mantidas)"))


def cmd_wg_show(_args) -> None:
    inventory = json.loads(INVENTORY_FILE.read_text(encoding="utf-8"))
    cfg = inventory["wireguard"]
    keys_file = WG_DIR / "keys.json"
    keys = json.loads(keys_file.read_text()) if keys_file.is_file() else {}
    print(f"{'nome':<22}{'IP na VPN':<14}chave pública")
    for item in [cfg["server"]] + cfg["peers"]:
        pub = keys.get(item["name"], {}).get("public", "(não gerada)")
        print(f"{item['name']:<22}{item['address']:<14}{pub}")


# ------------------------------------------------- dispositivos sem mTLS (Wokwi)
# O ESP32 do Wokwi (versão web gratuita) só alcança brokers públicos. Como
# controle compensatório, ele assina cada mensagem com HMAC-SHA256 usando uma
# chave exclusiva dele; a ponte da borda valida a assinatura antes de repassar.
def make_hmac(name: str) -> None:
    data = {
        "device_id": name,
        "key_hex": secrets.token_hex(32),          # 256 bits
        # prefixo aleatório: o tópico no broker público não é adivinhável
        "topic_prefix": f"vilaaurora-lab/{secrets.token_hex(8)}",
        "created_at": utcnow().isoformat(),
    }
    write_file(HMAC_DIR / f"{name}.json",
               json.dumps(data, indent=2).encode(), 0o600)
    print(f"[ok] hmac    {name}")
    show_hmac(name)


def show_hmac(name: str) -> None:
    path = HMAC_DIR / f"{name}.json"
    if not path.is_file():
        sys.exit(f"{name} não tem chave HMAC (ou o Docker criou uma pasta no lugar). "
                 "Rode: docker compose down  e depois  python pki/pki.py issue-all")
    data = json.loads(path.read_text())
    print("\n  Cole no main.py do Wokwi:")
    print(f'    DEVICE_ID    = "{data["device_id"]}"')
    print(f'    TOPIC_PREFIX = "{data["topic_prefix"]}"')
    print(f'    HMAC_KEY_HEX = "{data["key_hex"]}"\n')


def cmd_hmac_show(args) -> None:
    show_hmac(args.name)


def cmd_hmac_rotate(args) -> None:
    make_hmac(args.name)
    print("Atualize o main.py no Wokwi e reinicie a ponte: docker compose restart escola-wokwi-bridge")


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

    p = sub.add_parser("hmac-show", help="mostra a chave HMAC de um ESP32 (Wokwi)")
    p.add_argument("name")
    p.set_defaults(func=cmd_hmac_show)

    p = sub.add_parser("hmac-rotate", help="gera nova chave HMAC para um ESP32 (Wokwi)")
    p.add_argument("name")
    p.set_defaults(func=cmd_hmac_rotate)

    sub.add_parser("wg-show", help="mostra o plano de endereços da VPN").set_defaults(func=cmd_wg_show)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
