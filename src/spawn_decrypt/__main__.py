#!/usr/bin/env python3
import sys
import argparse
from pathlib import Path

from .author import authorize
from .decrypt import decrypt_asset
from .wallet_gen import save_wallet_jwk


def parse_args_for_authorize():
    parser = argparse.ArgumentParser(
        prog="spawn-authorize",
        description="Authorize a new user for a Spawn contract"
    )
    parser.add_argument(
        "caller_wallet",
        nargs="?",
        help="[optional] Path to your wallet JWK JSON (admin/agent or existing authorized user)"
    )
    parser.add_argument(
        "new_user_wallet",
        help="Path to the new user's wallet JWK JSON"
    )
    parser.add_argument(
        "contract_or_spwn",
        help="SmartWeave contract TX ID or path to a .spwn package"
    )
    parser.add_argument(
        "--key-file", "-k",
        dest="key_file",
        help="Optional path to wrapped AES key file (admin/agent flow)"
    )
    return parser.parse_args()


def run_authorize():
    args = parse_args_for_authorize()
    sys.exit(authorize(
        caller_wallet    = args.caller_wallet,
        new_user_wallet  = args.new_user_wallet,
        contract_or_spwn = args.contract_or_spwn,
        key_file         = args.key_file,
    ))


def parse_args_for_decrypt():
    parser = argparse.ArgumentParser(
        prog="spawn-decrypt",
        description="Fetch, decrypt, and reassemble a Spawn-protected .m4a"
    )
    parser.add_argument(
        "wallet",
        help="Path to your wallet JWK JSON (authorized user or admin)"
    )
    parser.add_argument(
        "source",
        help=".spwn package file or SmartWeave transaction ID"
    )
    parser.add_argument(
        "--key-file", "-k",
        dest="key_file",
        help="Optional path to wrapped AES key file (admin/agent flow)"
    )
    parser.add_argument(
        "--auth-tx",
        dest="auth_tx",
        help="Optional SmartWeave contract ID (override if not in package)"
    )
    return parser.parse_args()


def run_decrypt():
    args = parse_args_for_decrypt()
    sys.exit(decrypt_asset(
        wallet_file = args.wallet,
        source      = args.source,
        key_file    = args.key_file,
        auth_tx     = args.auth_tx,
    ))


def main():
    prog = Path(sys.argv[0]).name
    if prog.endswith("spawn-authorize"):
        run_authorize()
    elif prog.endswith("spawn-decrypt"):
        run_decrypt()
    else:
        parser = argparse.ArgumentParser(
            prog="spawn-tools",
            description="Spawn tools CLI"
        )
        subs = parser.add_subparsers(dest="cmd", required=True)
        subs.add_parser("authorize", help="Authorize a new user").set_defaults(func=run_authorize)
        subs.add_parser("decrypt",   help="Decrypt a .spwn package").set_defaults(func=run_decrypt)
        args = parser.parse_args()
        args.func()

def run_gen_wallet():
    out_path = save_wallet_jwk(args.output)
    print(f"Wallet JSON written to {out_path}")

if __name__ == "__main__":
    main()