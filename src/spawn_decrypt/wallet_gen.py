#!/usr/bin/env python3
"""
wallet_gen.py

Module for generating and saving Arweave wallet JSON (JWK RSA 4096-bit key pair).
"""

import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def _b64url_uint(i: int) -> str:
    """Encode an integer to Base64URL without padding."""
    b = i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def generate_wallet_jwk() -> dict:
    """
    Generate a JWK dictionary for an Arweave wallet (RSA 4096-bit).
    Returns:
        dict: The JWK representing the RSA key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    priv_numbers = private_key.private_numbers()
    pub_numbers = priv_numbers.public_numbers

    jwk = {
        "kty": "RSA",
        "n": _b64url_uint(pub_numbers.n),
        "e": _b64url_uint(pub_numbers.e),
        "d": _b64url_uint(priv_numbers.d),
        "p": _b64url_uint(priv_numbers.p),
        "q": _b64url_uint(priv_numbers.q),
        "dp": _b64url_uint(priv_numbers.dmp1),
        "dq": _b64url_uint(priv_numbers.dmq1),
        "qi": _b64url_uint(priv_numbers.iqmp),
    }
    return jwk


def _find_project_root() -> Path:
    """
    Find the project root directory by looking for 'pyproject.toml' in the current working directory or ancestors.
    Returns:
        Path: The path to the project root, or cwd if not found.
    """
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    return cwd


def save_wallet_jwk(path: str = None, jwk: dict = None) -> str:
    """
    Save the JWK JSON to a file.
    Args:
        path (str, optional): Output file path. If provided, write there (overwrites). Defaults to project_root/arweave_wallet.json.
        jwk (dict, optional): JWK dict to save. If None, generates a new one.
    Returns:
        str: The path to which the JSON was written.
    """
    if jwk is None:
        jwk = generate_wallet_jwk()
    if path:
        out = Path(path)
    else:
        root = _find_project_root()
        base = "arweave_wallet"
        ext = ".json"
        out = root / f"{base}{ext}"
        if out.exists():
            idx = 1
            while True:
                candidate = root / f"{base}_{idx}{ext}"
                if not candidate.exists():
                    out = candidate
                    break
                idx += 1
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        json.dump(jwk, f, indent=2)
    return str(out)


def main():
    """CLI entrypoint."""
    import argparse
    parser = argparse.ArgumentParser(description="Generate Arweave wallet JWK JSON")
    parser.add_argument(
        "-o", "--output",
        help="Output file path. Defaults to project root/arweave_wallet.json"
    )
    args = parser.parse_args()
    out = save_wallet_jwk(args.output)
    print(f"Wallet JSON written to {out}")


if __name__ == "__main__":
    main()
