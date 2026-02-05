#!/usr/bin/env python3
"""
Generate a local PKI for mTLS (Manager/Admin/Agent) and RabbitMQ TLS.

Hierarchy:
  Root CA  (self-signed, 10 years)
    └─ Intermediate CA  (signed by root, 5 years)
         ├─ Manager server cert  (825 days)
         ├─ Admin client cert    (825 days)
         ├─ Agent client cert    (825 days)
         └─ RabbitMQ server cert (825 days)

Also generates a CRL (Certificate Revocation List) stub file.

Usage:
  python gen_certs.py --out ../certs --cn-manager manager.local --cn-admin admin.local --cn-agent agent-001.local
"""
from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_chain(path: Path, *certs: x509.Certificate) -> None:
    """Write a PEM certificate chain file (leaf first, then intermediates)."""
    data = b""
    for cert in certs:
        data += cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(data)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _mk_ca(cn: str, days: int = 3650, path_length=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = _name(cn)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mk_intermediate(cn: str, root_key, root_cert, days: int = 1825):
    """Create an intermediate CA signed by the root."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )
    return key, cert


def _mk_cert(
    cn: str,
    ca_key,
    ca_cert,
    *,
    is_server: bool,
    days: int = 825,
    san_dns: list[str] | None = None,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if is_server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)

    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert


def _mk_empty_crl(ca_key, ca_cert) -> x509.CertificateRevocationList:
    """Generate an empty CRL signed by the CA."""
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=30))
    )
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output directory (e.g., ../certs)")
    ap.add_argument("--cn-manager", default="manager.local")
    ap.add_argument("--cn-admin", default="admin.local")
    ap.add_argument("--cn-agent", default="agent-001.local")
    ap.add_argument("--cn-rabbitmq", default="rabbitmq.local")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # --- Root CA (10 years, offline) ---
    root_key, root_cert = _mk_ca("edge-root-ca", days=3650, path_length=1)
    _write_key(out / "ca.key", root_key)
    _write_cert(out / "ca.crt", root_cert)

    # --- Intermediate CA (5 years, signs all leaf certs) ---
    inter_key, inter_cert = _mk_intermediate("edge-intermediate-ca", root_key, root_cert, days=1825)
    _write_key(out / "intermediate.key", inter_key)
    _write_cert(out / "intermediate.crt", inter_cert)

    # Full chain: intermediate + root (used for verification)
    _write_chain(out / "ca-chain.crt", inter_cert, root_cert)

    # Empty CRL signed by intermediate CA
    crl = _mk_empty_crl(inter_key, inter_cert)
    (out / "crl.pem").write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    # --- Manager server (mTLS) — signed by intermediate ---
    mgr_dir = out / "manager"
    mgr_dir.mkdir(exist_ok=True)
    m_key, m_crt = _mk_cert(args.cn_manager, inter_key, inter_cert, is_server=True,
                           san_dns=[args.cn_manager, "manager", "localhost"])
    _write_key(mgr_dir / "server.key", m_key)
    _write_cert(mgr_dir / "server.crt", m_crt)
    _write_chain(mgr_dir / "ca.crt", inter_cert, root_cert)  # full chain for verification

    # --- Admin client — signed by intermediate ---
    admin_dir = out / "admin"
    admin_dir.mkdir(exist_ok=True)
    a_key, a_crt = _mk_cert(args.cn_admin, inter_key, inter_cert, is_server=False)
    _write_key(admin_dir / "client.key", a_key)
    _write_cert(admin_dir / "client.crt", a_crt)
    _write_chain(admin_dir / "ca.crt", inter_cert, root_cert)

    # --- Agent client — signed by intermediate ---
    agent_dir = out / "agent"
    agent_dir.mkdir(exist_ok=True)
    g_key, g_crt = _mk_cert(args.cn_agent, inter_key, inter_cert, is_server=False)
    _write_key(agent_dir / "client.key", g_key)
    _write_cert(agent_dir / "client.crt", g_crt)
    _write_chain(agent_dir / "ca.crt", inter_cert, root_cert)

    # --- RabbitMQ server cert (TLS for AMQP) — signed by intermediate ---
    rb_dir = out / "rabbitmq"
    rb_dir.mkdir(exist_ok=True)
    r_key, r_crt = _mk_cert(args.cn_rabbitmq, inter_key, inter_cert, is_server=True,
                           san_dns=[args.cn_rabbitmq, "rabbitmq", "localhost"])
    _write_key(rb_dir / "server.key", r_key)
    _write_cert(rb_dir / "server.crt", r_crt)
    _write_chain(rb_dir / "ca.crt", inter_cert, root_cert)

    print("Certificates generated under:", out)
    print("  PKI hierarchy: Root CA -> Intermediate CA -> Leaf certs")
    print("  CRL: crl.pem (empty, signed by intermediate)")
    print("  Chain: ca-chain.crt (intermediate + root)")


if __name__ == "__main__":
    main()
