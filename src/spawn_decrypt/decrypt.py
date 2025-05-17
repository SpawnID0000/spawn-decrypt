# src/spawn_decrypt/decrypt.py
"""
Module: Provides `decrypt_asset` function to fetch, decrypt, and reassemble a Spawn-protected .m4a file.
"""

import sys
import os
import json
import base64
import requests
import tempfile
import subprocess
import ctypes
import platform

from zipfile import ZipFile
from pathlib import Path
from typing import Optional, Tuple
from ast import literal_eval
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from mutagen.mp4 import MP4, MP4FreeForm, MP4Cover
from arweave import Wallet

import shutil

# Locate MP4Box if available
mp4box_path = shutil.which("MP4Box")


# ─── Native crypto library setup ──────────────────────────────────────────────
def load_spawncrypt():
    base_dir = os.path.dirname(__file__)
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        if "arm" in machine or "aarch64" in machine:
            libname = "libspawncrypt_rpi.so"
        else:
            libname = "libspawncrypt.so"
    elif system == "Darwin":
        libname = "libspawncrypt.dylib"
    elif system == "Windows":
        libname = "libspawncrypt.dll"
    else:
        raise RuntimeError(f"Unsupported platform: {system} ({machine})")

    return ctypes.CDLL(os.path.join(base_dir, libname))

_lib = load_spawncrypt()
_lib.unwrap_aes_key.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t)
]
_lib.unwrap_aes_key.restype = ctypes.c_int
_lib.scleanup.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_lib.scleanup.restype = None


_lib.unwrap_aes_key.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.POINTER(ctypes.c_size_t)
]
_lib.unwrap_aes_key.restype = ctypes.c_int
_lib.scleanup.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_lib.scleanup.restype = None


# ─── Helpers ────────────────────────────────

def base64url_to_int(val: str) -> int:
    padding_needed = (-len(val)) % 4
    val += "=" * padding_needed
    return int.from_bytes(base64.urlsafe_b64decode(val), 'big')


def compute_arweave_address(wallet_dict: dict) -> str:
    pub = {k: wallet_dict[k] for k in ("kty", "n", "e")}
    can = json.dumps(pub, separators=(',', ':'), sort_keys=True)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(can.encode())
    return base64.urlsafe_b64encode(digest.finalize()).rstrip(b"=").decode()


def fetch_spwn_from_contract(tx_id: str) -> Tuple[str, str]:
    """
    Fetch the .spwn from on-chain state or GraphQL, returning (local_path, spawn_id).
    """
    # 1) Try Warp gateway state endpoint
    try:
        warp_url = f"https://arweave.net/contract/{tx_id}/state"
        r = requests.get(warp_url, timeout=10)
        r.raise_for_status()
        file_url = r.json().get("fileUrl")
        if file_url:
            return _download_spwn_from_url(file_url, tx_id)
    except Exception:
        pass

    # 2) Fallback: GraphQL for updateFileUrl
    graphql = {
        "query": f"""
        {{
          transactions(
            tags: [
              {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
              {{ name: "Contract",  values: ["{tx_id}"] }},
              {{ name: "App-Action", values: ["updateFileUrl"] }}
            ],
            first: 1,
            sort: HEIGHT_DESC
          ) {{ edges {{ node {{ id }} }} }}
        }}
        """
    }
    try:
        g = requests.post("https://arweave.net/graphql", json=graphql, timeout=10)
        g.raise_for_status()
        edges = g.json()["data"]["transactions"]["edges"]
        if not edges:
            raise RuntimeError("No updateFileUrl interactions found")
        interaction_tx = edges[0]["node"]["id"]
        d = requests.get(f"https://arweave.net/tx/{interaction_tx}/data", timeout=10)
        d.raise_for_status()
        try:
            payload = d.json()
        except Exception:
            raw = d.content
            pad = b"=" * ((4 - len(raw) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(raw + pad).decode())
        file_url = payload.get("fileUrl")
        if not file_url:
            raise RuntimeError("updateFileUrl payload missing fileUrl")
        return _download_spwn_from_url(file_url, tx_id)
    except Exception as e:
        raise RuntimeError(f"Could not fetch fileUrl: {e}")


def _download_spwn_from_url(file_url: str, tx_id: str) -> Tuple[str, str]:
    """
    Download a .spwn from a URL (JSON metadata or raw ZIP).
    Returns (local_spwn_path, spawn_id).
    """
    resp = requests.get(file_url, stream=True, timeout=10)
    resp.raise_for_status()
    ct = resp.headers.get("Content-Type", "")
    if ct.startswith("application/json"):
        meta = resp.json()
        name = meta.get("name")
        if not name or not name.lower().endswith(".spwn"):
            raise RuntimeError("Metadata JSON missing valid 'name'")
        spawn_id = os.path.splitext(name)[0]
        data_tx = meta.get("dataTxId") or meta.get("dataTxID")
        if not data_tx:
            raise RuntimeError("Metadata JSON missing 'dataTxId'")
        download_url = f"https://arweave.net/{data_tx}"
        rdata = requests.get(download_url, stream=True, timeout=10)
        rdata.raise_for_status()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".spwn")
        for chunk in rdata.iter_content(16_384):
            tmp.write(chunk)
        tmp.close()
        return tmp.name, spawn_id

    # Otherwise assume file_url is the .spwn itself
    spawn_id = tx_id
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".spwn")
    for chunk in resp.iter_content(16_384):
        tmp.write(chunk)
    tmp.close()
    return tmp.name, spawn_id


def extract_spwn_package(package_path: str, temp_dir: str) -> None:
    try:
        with ZipFile(package_path, 'r') as zf:
            zf.extractall(temp_dir)
    except Exception as e:
        raise RuntimeError(f"Failed to extract package: {e}")


def find_encrypted_audio_file(temp_dir: str, spawn_id: str) -> str:
    for fn in os.listdir(temp_dir):
        if fn.startswith(f"{spawn_id}_data") and (fn.endswith(".nora") or fn.endswith(".norA")):
            return os.path.join(temp_dir, fn)
    raise RuntimeError("Encrypted audio file not found in package.")


def decrypt_audio_file(encrypted_file: str, aes_key: bytes, spawn_id: str) -> bytes:
    # 1) Read the entire encrypted file into immutable bytes
    data = Path(encrypted_file).read_bytes()
    if len(data) < 12:
        raise RuntimeError("Encrypted file data is too short.")

    # 2) Extract nonce and ciphertext portion
    nonce = data[:12]
    ciphertext = data[12:]

    # 3) Copy into a mutable buffer for decryption & zeroization
    tmp = bytearray(ciphertext)

    try:
        # 4) Decrypt using the mutable buffer only
        plaintext = AESGCM(aes_key).decrypt(
            nonce,
            bytes(tmp),
            spawn_id.encode()
        )
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt audio file: {e}")
    finally:
        # 5) Zero and delete the mutable buffer
        for i in range(len(tmp)):
            tmp[i] = 0
        del tmp

    # 6) Clean up references to the original data
    del ciphertext
    del data

    return plaintext


def clean_metadata_value(value):
    if isinstance(value, str):
        v = value.strip()
        if v.startswith("b'") and v.endswith("'"):
            return v[2:-1]
    return value


def embed_metadata_and_cover(output_filename: str, temp_dir: str, spawn_id: str) -> None:
    metadata_file = None
    cover_file = None
    for fn in os.listdir(temp_dir):
        if fn.startswith(spawn_id) and "_meta" in fn and fn.endswith(".json"):
            metadata_file = os.path.join(temp_dir, fn)
        elif fn.startswith(spawn_id) and "cover" in fn and fn.endswith(".jpg"):
            cover_file = os.path.join(temp_dir, fn)

    metadata_json = {}
    if metadata_file:
        try:
            metadata_json = json.load(open(metadata_file, "r", encoding="utf-8"))
        except Exception:
            pass

    audio = MP4(output_filename)
    for tag, val in metadata_json.items():
        cleaned = [clean_metadata_value(v) for v in (val if isinstance(val, list) else [val])]
        if tag in ("trkn", "disk"):
            try:
                tpl = literal_eval(cleaned[0])
                audio[tag] = [tpl]
            except Exception:
                audio[tag] = cleaned
        elif tag.startswith("----:"):
            joined = " / ".join(cleaned)
            audio[tag] = [MP4FreeForm(joined.encode("utf-8"), dataformat=1)]
        else:
            audio[tag] = cleaned

    if cover_file:
        try:
            cover_data = open(cover_file, "rb").read()
            audio["covr"] = [MP4Cover(cover_data, imageformat=MP4Cover.FORMAT_JPEG)]
        except Exception:
            pass

    audio.save()


def inject_udta_into_container(udta_file: str, m4a_file: str) -> None:
    if not mp4box_path:
        return
    cmd = [mp4box_path, "-udta", udta_file, m4a_file]
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def inject_original_container_metadata(temp_dir: str, spawn_id: str, output_filename: str) -> None:
    for fn in os.listdir(temp_dir):
        if fn.startswith(spawn_id) and "udta" in fn and fn.endswith(".bin"):
            inject_udta_into_container(os.path.join(temp_dir, fn), output_filename)
            break


# ─── Primary function ─────────────────────────────────────

def decrypt_asset(
    wallet_file: str,
    source: str,
    key_file: Optional[str] = None,
    auth_tx: Optional[str] = None,
    output_dir: Optional[str] = None
) -> int:
    """
    Fetch, decrypt, and reassemble a Spawn-protected .m4a file.
    """
    try:
        # 1. Load Arweave wallet (for metadata)
        _ = Wallet(wallet_file)

        # 2. Get .spwn and spawn_id
        if os.path.isfile(source) and source.lower().endswith(".spwn"):
            spwn_path = source
            spawn_id = Path(spwn_path).stem
        else:
            spwn_path, spawn_id = fetch_spwn_from_contract(source)

        # 3. Obtain wrapped AES key
        if key_file:
            wrapped_bytes = Path(key_file).read_bytes()
        else:
            # figure out contract_tx_id
            if auth_tx:
                contract_tx_id = auth_tx
            else:
                info = json.loads(
                    ZipFile(spwn_path, 'r').read(f"{spawn_id}_contract_info.json")
                )
                contract_tx_id = info["contractTxId"]

            # — secure-load wallet JWK and immediately delete it after use
            with open(wallet_file, "r", encoding="utf-8") as jwf:
                jwk = json.load(jwf)
            caller_addr = compute_arweave_address(jwk)
            # wipe and remove the wallet dict
            for k in list(jwk):
                jwk[k] = None
            del jwk

            # ——— GraphQL lookup ———
            gql = {
                "query": f"""
                {{
                  transactions(
                    tags: [
                      {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
                      {{ name: "Contract",  values: ["{contract_tx_id}"] }},
                      {{ name: "App-Action", values: ["authorize"] }}
                    ],
                    first: 100,
                    sort: HEIGHT_DESC
                  ) {{ edges {{ node {{ id }} }} }}
                }}
                """
            }
            resp = requests.post("https://arweave.net/graphql", json=gql, timeout=5)
            resp.raise_for_status()
            edges = resp.json()["data"]["transactions"]["edges"]

            wrapped_b64 = None
            for edge in edges:
                txid = edge["node"]["id"]
                try:
                    r = requests.get(f"https://arweave.net/{txid}", timeout=5)
                    r.raise_for_status()
                    raw_bytes = r.content
                except Exception:
                    continue

                # parse JSON or base64‐wrapped JSON
                try:
                    payload = json.loads(raw_bytes)
                except Exception:
                    pad = b"=" * ((4 - len(raw_bytes) % 4) % 4)
                    try:
                        payload = json.loads(base64.urlsafe_b64decode(raw_bytes + pad))
                    except Exception:
                        continue

                if payload.get("user", "").rstrip("=") == caller_addr.rstrip("="):
                    wrapped_b64 = payload.get("wrappedKey")
                    break

            if not wrapped_b64:
                raise RuntimeError(f"No wrappedKey found for {caller_addr}")

            # decode to bytes
            wrapped_bytes = base64.urlsafe_b64decode(
                wrapped_b64 + "=" * ((4 - len(wrapped_b64) % 4) % 4)
            )

        # 4. Native unwrap AES key
        wrapped_buf = bytearray(wrapped_bytes)
        wrapped_len = len(wrapped_buf)
        wrapped_ba = (ctypes.c_ubyte * wrapped_len).from_buffer_copy(wrapped_buf)
        for i in range(wrapped_len):
            wrapped_buf[i] = 0
        del wrapped_buf
        out_key_ptr = ctypes.POINTER(ctypes.c_ubyte)()
        out_key_len = ctypes.c_size_t()
        rc = _lib.unwrap_aes_key(
            wallet_file.encode('utf-8'),
            wrapped_ba, wrapped_len,
            ctypes.byref(out_key_ptr), ctypes.byref(out_key_len)
        )
        del wrapped_ba
        if rc != 0:
            print(f"[ERROR] AES‐key unwrap failed (code {rc})", file=sys.stderr)
            return rc

        # pull out the raw key bytes and then zero & free the C buffer
        raw_key = ctypes.string_at(out_key_ptr, out_key_len.value)
        _lib.scleanup(out_key_ptr, out_key_len.value)

        # convert to a mutable buffer so we can zero it later
        aes_key = bytearray(raw_key)
        # drop the immutable raw_key immediately
        del raw_key

        # 5. Decrypt and reassemble
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_spwn_package(spwn_path, tmpdir)
            enc_file   = find_encrypted_audio_file(tmpdir, spawn_id)

            # 5a) Decrypt asset (helper will zero the ciphertext buffer)        # !!!
            decrypted = decrypt_audio_file(enc_file, aes_key, spawn_id)         # !!!

            # 5b) Securely zero and delete the AES key immediately              # !!!
            for i in range(len(aes_key)):                                       # !!!
                aes_key[i] = 0                                                  # !!!
            del aes_key 

            # decide where to write the output file
            if output_dir:
                out_path = Path(output_dir) / f"{spawn_id}.m4a"
            else:
                out_path = Path(f"{spawn_id}.m4a")
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(decrypted)
            del decrypted

            # embed metadata and re-inject udta using the new path
            embed_metadata_and_cover(str(out_path), tmpdir, spawn_id)
            inject_original_container_metadata(tmpdir, spawn_id, str(out_path))

        msg = f"✅ Decrypted audio saved as: {out_path}"
        try:
            print(msg)
        except UnicodeEncodeError:
            print(msg.encode('utf-8', 'replace').decode('ascii', 'ignore'))
        return 0

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1