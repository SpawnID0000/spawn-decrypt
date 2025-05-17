# spawn-decrypt

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](#license) [![GitHub Release](https://img.shields.io/github/v/release/SpawnID0000/spawn-decrypt)](https://github.com/SpawnID0000/spawn-decrypt/releases)

## Overview

**spawn-decrypt** offers both command-line and graphical (Tkinter) tools to:

- **Authorize** new users on a Spawn SmartWeave contract (`spawn-authorize`).
- **Decrypt** audio files encoded in NORA format and contained in a SPWN package (`spawn-decrypt`).
- **Generate** Arweave wallet JWKs for use as new keys (`wallet_gen` via GUI or module).

Under the hood, spawn-decrypt wraps/unwraps AES keys with a proprietary C library and interacts with Arweave’s network.

## Prerequisites

- **Python 3.7+**
- **Tkinter** (for `spawn-gui`): ensure your Python build includes Tcl/Tk support. On macOS, the python.org installer bundles it; with pyenv you may need `brew install tcl-tk` and rebuild.
- **MP4Box** (optional): for injecting original container data back into .m4a (if installed, available on $PATH).

## Installation

### Install from GitHub

```bash
pip install --upgrade pip
pip install git+https://github.com/SpawnID0000/spawn-decrypt.git@main
```

Or install a specific release tag:

```bash
pip install git+https://github.com/SpawnID0000/spawn-decrypt.git@v0.0.3
```

### Install from Source (Editor / Development)

```bash
git clone https://github.com/SpawnID0000/spawn-decrypt.git
cd spawn-decrypt
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

## Wallet Generation

You can create a new Arweave wallet key pair (JWK) in two ways:

- **GUI**: In either the **Authorize** or **Decrypt** tab, click **Generate Wallet**.  A new `arweave_wallet.json` (or `arweave_wallet_#.json`) appears in the project root.

- **CLI / Module**:

  ```bash
  python3 -m spawn_decrypt.wallet_gen [-o <output_path>]
  ```

  By default writes to `./arweave_wallet.json`, or to the next available `arweave_wallet_1.json`, etc.

## Configuration (`settings.env`)

The GUI persists its fields in `src/spawn_decrypt/settings.env`. The following keys may appear:

```ini
# Authorize tab
NEW_USER_WALLET=/path/to/new_user_wallet.json
CONTRACT_OR_SPWN=/path/to/package.spwn or <contract_tx_id>
KEY_FILE=/path/to/wrapped_key.bin        # optional
CALLER_WALLET=/path/to/authorized_wallet.json  # optional

# Decrypt tab
OUTPUT_DIR=/path/to/output_directory    # optional
DEC_WALLET=/path/to/authorized_wallet.json
SOURCE=/path/to/package.spwn or <contract_tx_id>
DEC_KEY_FILE=/path/to/wrapped_key.bin    # optional
AUTH_TX=<contract_tx_id>                 # optional override
```

To manually copy the template (when installed from VCS):

```bash
cp $(python3 -c "import spawn_decrypt; print(Path(spawn_decrypt.__file__).parent / 'settings.env')") ./settings.env
```  
Then edit paths/IDs as needed.

## Usage

### CLI Tools

#### spawn-authorize

Wraps and rewraps the AES key for a new user, and submits an on-chain interaction:

```bash
spawn-authorize [caller_wallet] <new_user_wallet> <contract_or_spwn> [-k <key_file>]
```

- `caller_wallet` (optional): existing admin/agent or authorized user JWK.
- `new_user_wallet`: path to the new user’s wallet JWK.
- `contract_or_spwn`: SmartWeave contract TX ID or `.spwn` package path.
- `-k, --key-file`: wrapped AES key (admin/agent flow).

#### spawn-decrypt

Fetches a `.spwn` package (locally or on-chain), unwraps the AES key, decrypts the audio, and reassembles metadata:

```bash
spawn-decrypt <wallet> <source> [-k <key_file>] [--auth-tx <tx_id>] [--output-dir <dir>]
```

- `wallet`: your authorized wallet JWK.
- `source`: `.spwn` package file or contract TX ID.
- `-k, --key-file`: wrapped AES key (admin/agent).
- `--auth-tx`: override the contract TX ID if not in the package.
- `--output-dir`: directory for `<spawn_id>.m4a` output (defaults to CWD).

#### spawn-tools

An umbrella CLI with subcommands:

```bash
spawn-tools authorize …
spawn-tools decrypt …
```

Note: `spawn-tools` is installed automatically alongside the two individual scripts.

#### Wallet Generation (module)

```bash
python3 -m spawn_decrypt.wallet_gen [-o <output_path>]
```

### GUI

```bash
spawn-gui
```

Opens a window with two tabs:

1. **Authorize**: fill in New User Wallet, Source, etc., then **Authorize** or **Generate Wallet**.
2. **Decrypt**: fill in Wallet, Source, optional fields, then **Decrypt** or **Generate Wallet**.

All printed output appears in the scrollable log panel.

## Bundled Libraries

This package includes precompiled C binaries for AES key operations:

- `libspawncrypt.so` / `libspawncrypt_rpi.so` (Linux)
- `libspawncrypt.dylib` (macOS)
- `libspawncrypt.dll` (Windows)

- **Redistribution** of these binaries is **permitted** and **required** for functionality.
- **Modifying** `author.py` or `decrypt.py` changes checksum logic and will prevent the native libraries from loading normally.
- The Python wrappers and logic remain MIT-licensed.

## Troubleshooting

- **`ModuleNotFoundError: No module named '_tkinter'`**: rebuild Python with Tcl/Tk support or use the python.org installer.
- **`MP4Box` not found**: UDTA injection is skipped, but metadata and cover art still embed correctly.
- **Network/API errors**: ensure you have connectivity and valid wallet files. Retry or increase timeout if needed.

## Contributing

Bug reports and pull requests are welcome:

- Issue Tracker: https://github.com/SpawnID0000/spawn-decrypt/issues
- Fork, branch, and open a PR against the `main` branch.

Please adhere to the MIT license for code contributions.

## License

This project is licensed under the [MIT License](LICENSE).

The bundled C libraries are proprietary but may be redistributed under the terms in the `LICENSE` file.
