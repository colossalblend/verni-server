# SPDX-License-Identifier: GPL-3.0-only
"""Генератор TLS-сертификата и ключа доступа для Verni-Desktop.

Ключ формата Verni Desktop (AccessKeyDialog -> remote_provider.py -> profile()):
    VERNI1.<base64url(json {endpoint, token, expires_unix, ca_pem})>

Команды:
  python make_key.py cert <hostname> [--days N]     self-signed cert.pem + key.pem
  python make_key.py key  [--days N] [--out файл]   генерирует verni-key.txt + .env.server
  python make_key.py all  <hostname> [--days N]     обе вещи сразу
"""
from __future__ import annotations

import argparse
import base64
import datetime
import ipaddress
import json
import re
import secrets
from pathlib import Path

HERE = Path(__file__).resolve().parent
CERT = HERE / "cert.pem"
KEY = HERE / "key.pem"
KEY_TXT = HERE / "verni-key.txt"
ENV_TXT = HERE / ".env.server"
DEFAULT_DAYS = 730
HOST_RE = re.compile(r"^[a-zA-Z0-9\.\-_]+$")


def gen_cert(hostname: str, days: int) -> None:
    if not HOST_RE.fullmatch(hostname):
        raise SystemExit("bad hostname")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise SystemExit("pip install cryptography") from None

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    sans = [x509.DNSName(hostname)]
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    except ValueError:
        pass
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"[ok] {CERT}")
    print(f"[ok] {KEY}")


def cert_hostname() -> str:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    cert = x509.load_pem_x509_certificate(CERT.read_bytes())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        return str(cn[0].value)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        if names:
            return str(names[0])
        ips = san.get_values_for_type(x509.IPAddress)
        if ips:
            return str(ips[0])
    except x509.ExtensionNotFound:
        pass
    return "localhost"


def gen_key(days: int, out: Path, endpoint: str = "") -> str:
    if not CERT.exists():
        raise SystemExit("нет cert.pem — сначала: python make_key.py cert <hostname>")
    if not endpoint:
        endpoint = cert_hostname()
    ca_pem = CERT.read_text(encoding="ascii").strip()
    token = secrets.token_hex(48)[:64]
    assert token[0].isalnum()  # [A-Za-z0-9_-] соблюдается по построению
    expires = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + days * 86400
    profile = {
        "endpoint": f"https://{endpoint}:18766",
        "token": token,
        "expires_unix": expires,
        "ca_pem": ca_pem,
    }
    key_text = "VERNI1." + base64.urlsafe_b64encode(
        json.dumps(profile, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).decode("ascii")
    out.write_text(key_text, encoding="ascii")
    env_line = f"VERNI_TOKEN={token}\n"
    ENV_TXT.write_text(env_line, encoding="ascii")
    when = datetime.datetime.fromtimestamp(expires, datetime.timezone.utc).isoformat()
    print(f"[ok] key: {out}")
    print(f"     endpoint https://{endpoint}:18766, valid to {when}")
    print(f"[ok] {ENV_TXT} (token for server.py)")


def main() -> None:
    parser = argparse.ArgumentParser(description="TLS + VERNI1 key generator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_opts(p, with_host: bool):
        if with_host:
            p.add_argument("hostname")
        p.add_argument("--days", type=int, default=DEFAULT_DAYS)
        p.add_argument("--out", type=Path, default=KEY_TXT)
        p.add_argument("--endpoint", default="")

    p_cert = sub.add_parser("cert")
    p_cert.add_argument("hostname")
    p_cert.add_argument("--days", type=int, default=DEFAULT_DAYS)

    p_key = sub.add_parser("key")
    add_opts(p_key, False)

    p_all = sub.add_parser("all")
    add_opts(p_all, True)

    args = parser.parse_args()
    if args.cmd == "cert":
        gen_cert(args.hostname, args.days)
    elif args.cmd == "key":
        gen_key(args.days, args.out, getattr(args, "endpoint", ""))
    else:
        gen_cert(args.hostname, args.days)
        gen_key(args.days, args.out)


if __name__ == "__main__":
    main()
