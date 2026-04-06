#!/usr/bin/env python3
"""
Elasticsearch License Forge Tool
Generates valid ES licenses signed with a custom RSA private key.

Usage:
    python3 elastic_forge.py --key private.pem --type platinum --issued-to "My Org" --max-nodes 1000 --days 3650
"""

import argparse
import base64
import json
import os
import struct
import sys
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Elasticsearch hardcoded constants
AES_SALT = bytes([0x74, 0x68, 0x69, 0x73, 0x69, 0x73, 0x74, 0x68,
                  0x65, 0x73, 0x61, 0x6C, 0x74, 0x77, 0x65, 0x75])  # "thisisthesaltweu"
AES_PASSPHRASE = b"elasticsearch-license"
PBKDF2_ITERATIONS = 10000
AES_KEY_LENGTH = 16  # 128-bit
LICENSE_VERSION = 5  # VERSION_CURRENT/VERSION_ENTERPRISE in ES 8.x/9.x


def derive_aes_key():
    """Derive AES key using ES's hardcoded PBKDF2 parameters."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=AES_KEY_LENGTH,
        salt=AES_SALT,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(AES_PASSPHRASE)


def pad_pkcs5(data, block_size=16):
    """PKCS#5/PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def encrypt_aes_ecb(plaintext, key):
    """Encrypt with AES-128-ECB (as ES does)."""
    padded = pad_pkcs5(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def build_spec_json(license_data, version=5):
    """Build the license JSON in spec view mode (the exact format ES signs).

    Field order must exactly match ES's toInnerXContent() with license_spec_view=true.
    Version 5 (VERSION_CURRENT/ENTERPRISE) includes max_resource_units.
    """
    spec = {}
    spec["uid"] = license_data["uid"]
    spec["type"] = license_data["type"]
    # Version 1 only: subscription_type
    spec["issue_date_in_millis"] = license_data["issue_date_in_millis"]
    # Version 1 only: feature
    spec["expiry_date_in_millis"] = license_data["expiry_date_in_millis"]
    if version >= 5:
        # Version 5+: max_nodes as nullable Integer (null if -1)
        max_nodes = license_data.get("max_nodes", 1000)
        spec["max_nodes"] = None if max_nodes == -1 else max_nodes
        # Version 5+: max_resource_units as nullable Integer (null if -1)
        max_ru = license_data.get("max_resource_units", -1)
        spec["max_resource_units"] = None if max_ru == -1 else max_ru
    else:
        spec["max_nodes"] = license_data["max_nodes"]
    spec["issued_to"] = license_data["issued_to"]
    spec["issuer"] = license_data["issuer"]
    if version >= 3:
        spec["start_date_in_millis"] = license_data["start_date_in_millis"]
    # ES uses compact JSON (no spaces)
    return json.dumps(spec, separators=(',', ':'))


def sign_license(spec_json_bytes, private_key):
    """Sign the spec JSON with SHA512withRSA."""
    signature = private_key.sign(
        spec_json_bytes,
        padding.PKCS1v15(),
        hashes.SHA512()
    )
    return signature


def build_signature_blob(spec_json_bytes, private_key, aes_key):
    """Assemble the full signature blob: version + magic + encrypted_content + rsa_sig."""
    # Generate magic bytes (random nonce)
    magic = os.urandom(13)

    # Encrypt the spec JSON with AES
    encrypted = encrypt_aes_ecb(spec_json_bytes, aes_key)
    encrypted_b64 = base64.b64encode(encrypted)

    # Sign the spec JSON with RSA
    rsa_sig = sign_license(spec_json_bytes, private_key)

    # Assemble: version(4) + magic_len(4) + magic + hash_len(4) + encrypted_b64 + sig_len(4) + rsa_sig
    blob = b""
    blob += struct.pack(">I", LICENSE_VERSION)
    blob += struct.pack(">I", len(magic))
    blob += magic
    blob += struct.pack(">I", len(encrypted_b64))
    blob += encrypted_b64
    blob += struct.pack(">I", len(rsa_sig))
    blob += rsa_sig

    return base64.b64encode(blob).decode("ascii")


def generate_license(args):
    """Generate a complete forged license."""
    # Load private key
    with open(args.key, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Derive AES key
    aes_key = derive_aes_key()

    # Build license data
    now = datetime.now(timezone.utc)
    issue_date = int(now.timestamp() * 1000)
    start_date = issue_date
    expiry_date = int((now + timedelta(days=args.days)).timestamp() * 1000)

    license_version = args.license_version

    # Enterprise licenses use max_resource_units instead of max_nodes
    if args.type == "enterprise":
        max_nodes = -1  # null in JSON
        max_resource_units = args.max_nodes  # use the --max-nodes value as resource units
    else:
        max_nodes = args.max_nodes
        max_resource_units = -1  # null in JSON

    license_data = {
        "uid": args.uid or str(uuid.uuid4()),
        "type": args.type,
        "issue_date_in_millis": issue_date,
        "expiry_date_in_millis": expiry_date,
        "max_nodes": max_nodes,
        "max_resource_units": max_resource_units,
        "issued_to": args.issued_to,
        "issuer": args.issuer,
        "start_date_in_millis": start_date,
    }

    # Build spec JSON (what gets signed) — must match what ES rebuilds from the license fields
    spec_json = build_spec_json(license_data, version=license_version)
    spec_json_bytes = spec_json.encode("utf-8")

    print(f"[*] License version: {license_version}")
    print(f"[*] License spec JSON: {spec_json}")
    print(f"[*] Spec JSON length: {len(spec_json_bytes)} bytes")

    # Build signature blob
    signature = build_signature_blob(spec_json_bytes, private_key, aes_key)

    # Assemble final license — MUST include the same fields as the spec JSON
    # so ES creates a License object with the correct version and fields
    license_data["signature"] = signature
    license_data["version"] = license_version

    final = {"license": license_data}

    # Write to file
    output_file = args.output
    with open(output_file, "w") as f:
        json.dump(final, f, indent=2)

    print(f"[+] Forged license written to: {output_file}")
    print(f"[+] Type: {args.type}")
    print(f"[+] Valid for: {args.days} days")
    print(f"[+] Max nodes: {args.max_nodes}")
    print(f"[+] Issued to: {args.issued_to}")
    print(f"[+] UID: {license_data['uid']}")

    return final


def extract_public_key(args):
    """Extract and save the public key from a private key (for replacing in ES jar)."""
    with open(args.key, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    pub_key = private_key.public_key()
    pub_der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    output = args.pub_output or "public.key"
    with open(output, "wb") as f:
        f.write(pub_der)

    print(f"[+] Public key (DER/X.509) written to: {output}")
    print(f"[+] Size: {len(pub_der)} bytes")

    # Also show base64 for reference
    print(f"[+] Base64: {base64.b64encode(pub_der).decode()}")


def main():
    parser = argparse.ArgumentParser(description="Elasticsearch License Forge Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Generate command
    gen = subparsers.add_parser("generate", help="Generate a forged license")
    gen.add_argument("--key", required=True, help="Path to RSA private key (PEM)")
    gen.add_argument("--type", default="platinum",
                     choices=["basic", "trial", "gold", "platinum", "enterprise"],
                     help="License type (default: platinum)")
    gen.add_argument("--issued-to", default="CTF Security Research", help="Issued to")
    gen.add_argument("--issuer", default="elastic-forge", help="Issuer name")
    gen.add_argument("--max-nodes", type=int, default=1000, help="Max nodes (default: 1000)")
    gen.add_argument("--days", type=int, default=3650, help="Validity in days (default: 3650)")
    gen.add_argument("--uid", help="License UID (auto-generated if omitted)")
    gen.add_argument("--license-version", type=int, default=5, choices=[3, 4, 5],
                     help="License format version (default: 5 for ES 8.x/9.x)")
    gen.add_argument("--output", default="forged_license.json", help="Output file")

    # Extract public key command
    pub = subparsers.add_parser("extract-pubkey", help="Extract public key for ES jar replacement")
    pub.add_argument("--key", required=True, help="Path to RSA private key (PEM)")
    pub.add_argument("--pub-output", default="public.key", help="Output file for public key")

    args = parser.parse_args()

    if args.command == "generate":
        generate_license(args)
    elif args.command == "extract-pubkey":
        extract_public_key(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
