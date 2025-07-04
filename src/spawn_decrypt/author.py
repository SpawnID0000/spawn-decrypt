# src/spawn_decrypt/author.py
"""
Module: Provides `authorize` function to onboard a new user to a Spawn contract.
"""

import sys
import json
import base64
import time
import requests
import ctypes
import platform

from zipfile import ZipFile
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from arweave import Wallet, Transaction

# ─── Native crypto library setup ──────────────────────────────────────────────

def get_lib_path():
    base = Path(__file__).parent / "lib"
    if platform.system() == "Darwin":
        return base / "libspawncrypt.dylib"
    elif platform.system() == "Windows":
        return base / "libspawncrypt.dll"
    else:  # Assume Linux
        return base / "libspawncrypt.so"

_lib = ctypes.CDLL(str(get_lib_path()))
_lib.unwrap_and_rewrap_key.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_size_t)
]
_lib.unwrap_and_rewrap_key.restype = ctypes.c_int

_lib.scleanup.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_lib.scleanup.restype = None
_lib.alittlehelp.restype = ctypes.c_char_p
_DEV_WALLET = ("0nIRVjcil2NMJXRVpXQy9VQYZ3YZF0U2sEMoNEVNZUWMlWThNnN4kXdr5EaNBVMy5kVIpkTylne5olMy1kYZBXUWplSOhXNSVjdBh0X0NmNv9lMpNWaDFEaylmRzQDe1ZjQy9Wcs1iZ0h0c3J1MkJkRmhXMtZkYiZXZ1ImeiNmeixEZj1EMD1WZ3o1Rto0Q4dDZUN1U5BVbyV2V5RHaEJEdJZWd2EGOKV1cn5WUzs0dOVnNW5mWBh0bphDW50WR0g3ZU50UzgESyFVRjJEVJZnSKBncjJDN2klWNlVbQNlZaVzdohFZ6ZUQWB3RNlETLx0S2UGZ3NGa15UaBhDUIJ3YvNVZEhFbLl0VvZTMVF0dypkS3NFR4pVb0UmcopFdoF2Z2FzVIVWMxJVejV3MfhHOIF2ULRDZphkWvJGemdkR1JTVWVGSDZmNyN3dp1SZI9WLuZFbjljaiojIpFnIsIyd0cGZh5EcTtkZCFXbUVET6lzSuxkUUp0T1cWOmtmUzR1a2UGb3gHb6FXaZhkY5pXYWBzXEVVWlxWdzN2RBZWR6BnMEBjQsl2ULNXSFZ2QJdGW0VjW4I3MGRVdsFVSIR2RnZUYJF0XYZVQzcDRXpWN5gmdltkVCRDZz0UbFJ3XLlmY2JjUIljYjJjM3EkYhFFd0FWSfpkVoFne5dkYxsWUKBDO1YWNjJzcFVUdSBzY1AHSRhjSjtkc1IWMUVHRyV3UOJ3UwIDZW9WL5h0bohGR4MmYIN0bzgWW1NlazQWLEhEazYTYxdGOt5mZpVTMpdjMQZmcS9GT09WO4xmSxglMsRWOyAXSCdXcVpXeKRHdzUXZyUHVldTUaFWbzQFUJlUbnlUasZnSmBnUjpUdyYmUBRzdyYHcYFmY2UzNPpkMzwERiREV2FXaolWSq1SOJ90N6BFa2InI6ISciwiIRdUeJtkWyBHb3V3V3dENtQ0SKpVO3F0YXx2VxckSsRXbO9kY0llSXVmMWdFSfp3S4kXWyUkeh1Ec0UWdtB1Qt1UTh1CVPFTYmNjVwZlMaJkdjBzRFJGdtFVSfNVewYGOUh0UM9USfdXeypUSiVVa2UjRyU2Mn90QiJUZPRXT2EHUkxWRSdXQrNXcrp1NMlTUoR3dRNXUykXQSpFWQ9mZyoER1F0USRmYK50SFhTcTplM6ZDW6hFVF52N0A1RUZzYqdFeBdkRyQ3UwQnVVxmSE1iSkR3ZkhmVFZ1S30yc3hFSsJjVMREUGFHcn9WWWVEZJFWeMBjUiZka052aPR3SzgXbFpVcFZHZEVkauhGWNJlaGhTOJJkWJx2QP9FML1ydsFjRrdXRWV2UIJ3cvNEZ2xmStUHUrtWO5JHe2M2Y1MGM4JWQFd1XTlHOX91ROhzb3FXZaBVeiojIwJCLiM3Q6FnblBHRudkUhlWc5FDZPFXTxJGO3EUMXxETIJjNiR0VYdzY5Qkbjl1NPdWbyMlSKNFdXhWRMpFbCxkQ0MWWYJzXNJ1Qnh1UPNXawFmdERDO0ZVOzd0M6tGawIWcWhlU1olMuxGWC9lQ3dnSHxWV1FTY3kVOk5kcNpEc1RmdMJVVBRHNFFVdMtWRZVjNkRlbRZGTm1UcjRlQ3NTS1oUbKlnWwwkeBl0Y4lTWUVlV41iWwQFRtNkaY9EU3p1ZpVTZrJleSh0SttmQNdWQi9WcBhkbR1kboV1SRVUcT5WS2g2XRN3XtU0Nqhjd6RnbJJ2NEl3QPFWdyFkdpl1UpdWZ1dkQnBFOrVEenV2ZyZmTlBFMzNWTqBXUiF3Q2AleGNjYz8mN2hWRLZ0aPNHW69WaYRVMVtWcxFEWMZ3R1YHVnZUTxgnM61kUyoFVhBlMrlULYJ1MjpnY3IjQOpEWNV0XU12TjFjT1l3dBVXZnZ1avNkeHR3SIFFRqVmWtclThdzR2UnNOFldxNjURJHc55mbxcWQs9mNUlma5QVO5YFMuJEN1cUL3hzS2VVSpNGVDZnaXh0XVdENPt2awYFZiFzbhBjWnplayFTOVFXO0NGcUF2VTdkYt9lNSVFb4UzYXVjTE5kS5JmM5kmM2VEdIdVM0plZUNlTfFleFBzXHVUQLlnN20SM09kZ1M2R6dDRlBlTYpmRrVlSfNDNCZ1T2Y3Q3NUMZFzTKVlWx02TTFnMNRzRtcFb4hTcvBlRQJUMwUzNyYTdwQDUWJXRDVzbX1SRm1CbChnbylVTVNFTCVFVXNkNxZWexkVZzNVdI1kY51SNHlkQ1MWMC90QLdXTNd3Vm12cQ9ld5YEM0pFTBRkdfRUL1FzUvRlY1ljY3dVUOVUWfFWLCRETTVWaiojIuJCLiE0USJiOikHdrJCLiIUQRFkI6ISZiwiIR1kbjdlNHVWYrZzMzJ0M1EFRyUXY4FTW6dWchxGcR9UbX12XGRTQup1b34Wa5lWOrFkTQdGO1cXRtRUO4I2VKJ2calDOK9lawoEMG5mdORTZ5I0RFFTRxYmQtY2Y2h2TYl0TUVEc6xEZrhWVmhXWNhlax0Ea4sWbxFza4oXO3lGdaNHcERkbI90YxVDSxF1U3ZlQMFjcJJjZjlkUClzVNBVQw50MQNTezdjUUB3TZNmQiRTL4VDcrVjejNWMIp1UEZmZhVVLS1SNuhmYNplQuNDWIZ1X5EDSs9lUaBjR4gFc5Ykaop2ZKdUNFJkTL9UOjZDSndWSZJ0UC9mbzUnUqNnT0YTT6hDRBt2MwsGW0RUQ6NVe0VmcZZWV5MkefVHNS9WYHBjSypVc2cXUY5mWWJkUpBHR1ske0B1XV92QoN0THdkWXFHdHJXQrFXY1dFZ2JWb1FVYiojIxRmIsISUrFUWOlmVtFEetE2N4skcoVTRGN0Ztk0cPR3Vld2bSlWVtEUTfB1Q11GeKtGajVja3VUOzg2TKRDW3ZlRshmZXxENFdVV59GRwQHdBdjZto2ZXh0XWJjQhx0Qw9EeYdEcF5Ucnp2RiZXeM9lY4AHSnRXcfxkcux0cZNkNGtEdudzN0FjTWNEaqJGeNBDd5BTMNR3XxokRBJDVy5mZ4lGRuhWVGdHVldzZi9GTqRnN391UzIUculkVrV1aV50dfZmRDVEMINDN1UWaEtUe6ZHatFWRGd0bwlGWutkUVt0TPJXSQRjQIRDW0RnYFBDd3p2Yp9UWXV1aWllSjdncVp2UGhzQs9UTilGT5FnU4QmNap3bycFVJZHVSdlb0ZGSFdmQvJEayd3Y6VGT5kWQU5mVShDdtQEVG1iNkV0c0oVb2YDcnZ0VuJnT1cFc0IHaUJ0T6NULxdlI6ICckJCLiUUe6RWMJN3cxM3SRJkYy00RRB3QHFTbkBjNyEjTBdDRTFkTGRXZCFUat8UT1gzb1QlNwE0UZJld1YGdfZ3UahlcycHO31EWG1GSKh2dYZDO2NEcIZ3cHtkWtFVT34me0UGTsVXNy9ULflGUhRmc1JHS5IDZBJGWotkRoRTONZTUJ9ldkpndVRnNzcWTKJXSmNTMPNHRYhEdkNlelFjTux0Uf9EeYhVbrxWS3FGWI1iW2MTZk1GSnpXaMFkNxolRkVUSPB3UphmUxwkamZURyFWRk1ydEZGc5t0ZJ1CaYJVVSlVaT9Wam5WLxN1S1Q2SnplWVRFardGMutmSkd0Uxp2MYpFNRFEcK1mSuJUR0UES3QkSLFmS1lGeJx2amdmU1U0aycjc1ljbSxmThtmcMhVWph2aOhFW3dFS5olMF9ldIVUbzFkbk9VV15WbZVGVEhzdNllZEVkc5pWT5FmcYRGdQJlS2c1QzsGdx8EdGJ2bq1GezJFO51yctMjZ5gUMCl2TJNGelRDZLZ2N6FFbSZTWrl0cPd0V5YVRTlTSTJ1blRFejJncChHVHBjZRhnR18FSSN1TaVndH5mctY2Zp1UYWNkamZzcyp0ZVhWR3lGVtRXVG5Eet91akJEMZdkUBd0baplUhRjcspUZutmToFFM1wGO5o3UGF2a1cTSvVnTwFTNtN3TmFEW2gUZUhkdQRne3BnVX9Wbqd3R2lzZFxGS5dUQxF2MHFVbLdUW5NEdyRXbUhHavRHcWZEa2pkRhhzS0cmUI9kRWhTUrFzVC1EMD12UjlDOwpnUDZmRNtkQ5V0THpUVZlmUkdzdzxmNGR2RW50cZtUU2A3XBhlVoxUW3ZTeE9lUkZFVsRXTIhUbUdFazgFMYF3bO90VLpWc5U3bVBzVMdnVK1UTiojIkJye")


# ─── Helpers ───────────────────────────────────────────────────────────────────

def base64url_to_int(val: str) -> int:
    """Convert a base64url string to an integer."""
    padding_needed = (-len(val)) % 4
    val += "=" * padding_needed
    return int.from_bytes(base64.urlsafe_b64decode(val), 'big')


def load_dev_wallet():
    lilhelp = _lib.alittlehelp().decode("utf-8")
    padding = "=" * ((4 - len(lilhelp) % 4) % 4)
    padplus = base64.urlsafe_b64decode(lilhelp + padding)
    helper = json.loads(padplus)
    wallet = json.loads(base64.urlsafe_b64decode(_DEV_WALLET[::-1] + "=" * ((4 - len(_DEV_WALLET[::-1]) % 4) % 4)))
    return wallet, helper


def compute_arweave_address(wallet_dict: dict) -> str:
    """Compute the Arweave address from a JWK dict."""
    pub = {k: wallet_dict[k] for k in ("kty", "n", "e")}
    can = json.dumps(pub, separators=(',', ':'), sort_keys=True)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(can.encode())
    addr = base64.urlsafe_b64encode(digest.finalize()).rstrip(b"=").decode()
    return addr


# ─── Main function ────────────────────────────────────────────────────────────

def authorize(
    caller_wallet: Optional[str],
    new_user_wallet: str,
    contract_or_spwn: str,
    key_file: Optional[str] = None
) -> Tuple[int, Optional[str]]:
    """
    Authorize a new user on-chain by wrapping the AES key for them and sending an authorize interaction.
    Returns:
      - (0, tx_id)         on a newly-submitted authorization
      - (0, None)          if the user was already pre-authorized
      - (exit_code, None)  on any error.

    Parameters:
        caller_wallet: Optional path to your wallet JWK JSON (admin/agent or existing authorized user).
        new_user_wallet: Path to the new user’s wallet JWK JSON.
        contract_or_spwn: SmartWeave contract TX ID or path to a .spwn package.
        key_file: Optional path to a wrapped AES key file (only for admin/agent flow).
    """

    # 1) Compute new user address
    try:
        with open(new_user_wallet, "r", encoding="utf-8") as f:
            user_jwk = json.load(f)
    except Exception as e:
        print(f"[ERROR] Cannot read new_user_wallet '{new_user_wallet}': {e}", file=sys.stderr)
        return 1, None
    user_addr = compute_arweave_address(user_jwk)
    #print(f"[DEBUG] New user_addr: {user_addr}")

    # 2) Determine contractTxId (direct or from .spwn)
    p = Path(contract_or_spwn)
    if p.is_file() and p.suffix.lower() == ".spwn":
        spawn_id = p.stem
        try:
            with ZipFile(p, "r") as zf:
                payload = zf.read(f"{spawn_id}_contract_info.json")
        except KeyError:
            print(f"[ERROR] {spawn_id}_contract_info.json not found in package", file=sys.stderr)
            return 1, None
        info = json.loads(payload.decode("utf-8"))
        contract_tx_id = info.get("contractTxId")
        if not contract_tx_id:
            print(f"[ERROR] contractTxId missing in {spawn_id}_contract_info.json", file=sys.stderr)
            return 1, None
    else:
        contract_tx_id = contract_or_spwn
    #print(f"[DEBUG] contract_tx_id: {contract_tx_id}")

    # 3) Prepare caller wallet
    if caller_wallet:
        caller_path = caller_wallet
    else:
        helper, d = load_dev_wallet()
        try:
            with NamedTemporaryFile("w", delete=False, suffix=".json", encoding="utf-8") as tf:
                json.dump(d, tf)
                caller_path = tf.name
        except Exception as e:
            print(f"[ERROR] Cannot write dev wallet temp file: {e}", file=sys.stderr)
            return 1, None

    # 4) Pre-authorization check
    try:
        graphql = {
            "query": f"""
            {{
              transactions(
                tags: [
                  {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
                  {{ name: "Contract",  values: ["{contract_tx_id}"] }},
                  {{ name: "App-Action", values: ["authorize"] }},
                  {{ name: "User",       values: ["{user_addr}"] }}
                ],
                first: 1
              ) {{
                edges {{ node {{ id }} }}
              }}
            }}
            """
        }
        resp = requests.post("https://arweave.net/graphql", json=graphql, timeout=10)
        resp.raise_for_status()
        edges = resp.json()["data"]["transactions"]["edges"]
        if edges:
            txid = edges[0]["node"]["id"]
            print(f"    {user_addr} already authorized in TX {txid}; skipping.")
            return 0, None
    except Exception as e:
        print(f"[DEBUG] Pre-auth check failed, continuing: {e}")

    # 5) Obtain wrapped_bytes (file-mode or contract-mode)
    if key_file:
        try:
            wrapped_bytes = Path(key_file).read_bytes()
        except Exception as e:
            print(f"[ERROR] Cannot read key_file '{key_file}': {e}", file=sys.stderr)
            return 1, None
    else:
        # contract-mode: scan GraphQL for authorize interactions
        try:
            with open(caller_path, "r", encoding="utf-8") as f:
                caller_jwk = json.load(f)
        except Exception as e:
            print(f"[ERROR] Cannot read caller_wallet '{caller_path}': {e}", file=sys.stderr)
            return 1, None
        caller_addr = compute_arweave_address(caller_jwk)
        #print(f"[DEBUG] caller_addr: {caller_addr}")

        graphql = {
            "query": f"""
            {{
              transactions(
                tags: [
                  {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
                  {{ name: "Contract",  values: ["{contract_tx_id}"] }},
                  {{ name: "App-Action", values: ["authorize"] }}
                ],
                first: 1000,
                sort: HEIGHT_DESC
              ) {{
                edges {{ node {{ id }} }}
              }}
            }}
            """
        }
        try:
            resp = requests.post("https://arweave.net/graphql", json=graphql, timeout=10)
            resp.raise_for_status()
            # DEBUG: dump entire GraphQL payload
            data = resp.json()
            #print(f"[DEBUG] GraphQL response: {json.dumps(data, indent=2)}")
            edges = data["data"]["transactions"]["edges"]
            #edges = resp.json()["data"]["transactions"]["edges"]
        except Exception as e:
            print(f"[ERROR] GraphQL query failed: {e}", file=sys.stderr)
            return 1, None

        #print(f"[DEBUG] Found {len(edges)} authorize interactions")

        wrapped_b64 = None
        for edge in edges:
            txid = edge["node"]["id"]
            #print(f"[DEBUG]   checking TX {txid}")
            try:
                d = requests.get(f"https://arweave.net/{txid}", timeout=10)
                d.raise_for_status()
                try:
                    #payload = json.loads(d.content)
                    payload = d.json()
                    #print(f"[DEBUG]    parsed payload: {json.dumps(payload)}")
                except json.JSONDecodeError:
                    raw = d.content.decode("utf-8", errors="ignore")
                    pad = "=" * ((4 - len(raw) % 4) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(raw + pad))
            #except Exception as e:
                #print(f"    [DEBUG] failed to fetch/parse payload: {e}")
            except Exception:
                continue

            user = payload.get("user")
            wrappedKey_val = payload.get("wrappedKey")
            #print(f"    [DEBUG] payload['user'] = {user!r}")
            #print(f"[DEBUG]    payload user={user!r}, wrappedKey present={'yes' if wrappedKey_val else 'no'}")

            if user == user_addr:
                print(f"    {user_addr} already pre-authorized in TX {txid}; skipping new authorize")
                msg = f"    {user_addr} already authorized by TX {txid}; skipping."
                try:
                    print(msg)
                except UnicodeEncodeError:
                    print(msg.encode('utf-8', 'replace').decode('ascii', 'ignore'))
                return 0, None
            if user == caller_addr and not wrapped_b64:
                wrapped_b64 = payload.get("wrappedKey")
                #print(f"[DEBUG] Found wrappedKey in {txid}")

        if not wrapped_b64:
            #print(f"[DEBUG] Final wrapped_b64: {wrapped_b64!r}")
            print(f"[ERROR] No authorize interaction found for {caller_addr}", file=sys.stderr)
            return 1, None

        pad = "=" * ((4 - len(wrapped_b64) % 4) % 4)
        wrapped_bytes = base64.urlsafe_b64decode(wrapped_b64 + pad)

    # 6) Native unwrap & re-wrap
    out_b64 = ctypes.c_char_p()
    out_len = ctypes.c_size_t()
    res = _lib.unwrap_and_rewrap_key(
        caller_path.encode(),
        (ctypes.c_ubyte * len(wrapped_bytes)).from_buffer_copy(wrapped_bytes), len(wrapped_bytes),
        new_user_wallet.encode(),
        ctypes.byref(out_b64), ctypes.byref(out_len)
    )
    if res != 0:
        print("[ERROR] Native wrap failed", file=sys.stderr)
        return 1, None
    wrapped_b64 = ctypes.string_at(out_b64, out_len.value).decode()
    _lib.scleanup(out_b64, out_len.value)

    #print(f"[DEBUG] Wrapped AES key for {user_addr}")


    # 7) Build and send transaction
    try:
        wallet = Wallet(caller_path)
        bal = wallet.balance
        if bal < 0.1:
            print(f"[ERROR] Wallet balance too low ({bal:.6f} AR). Top up and try again.", file=sys.stderr)
            return 1, None
        interaction = {"function": "authorize", "user": user_addr, "wrappedKey": wrapped_b64}
        tx = Transaction(wallet, data=json.dumps(interaction))
        tx.add_tag("App-Name", "SmartWeaveAction")
        tx.add_tag("App-Action", "authorize")
        tx.add_tag("Contract", contract_tx_id)
        tx.add_tag("User", user_addr)
        tx.add_tag("Content-Type", "application/json")
        #print(f"[DEBUG] Signing with {caller_path}…")
        tx.sign()
        print("Sending transaction to network, which can sometimes take a few minutes to be confirmed on-chain.")
        tx.send()
        # --- DEBUG: Transaction submitted ---
        #status_url = f"https://arweave.net/tx/{tx.id}"
        status_url = f"https://arweave.net/tx/{tx.id}/status"
        #print(f"     tx.id = {tx.id}")
        #print(f"     polling {status_url}")
        print("Feel free to do some jumping jacks while you wait...")
    except Exception as e:
        print(f"[ERROR] Failed to build/send transaction: {e}", file=sys.stderr)
        return 1, None

    # Cleanup dev wallet file if used
    if not caller_wallet:
        try:
            Path(caller_path).unlink()
        except Exception:
            pass

    # 8) Wait for on-chain confirmation
    #    poll the /tx endpoint (it returns 404 until the TX is seen, then 200)
    status_url = f"https://arweave.net/tx/{tx.id}/status"
    #status_url = f"https://arweave.net/tx/{tx.id}"
    tidbits = [
        "Still waiting... how many jumping jacks have you done so far?",
        "Still waiting, but hey - instant gratification is overrated anyway...",
        "Still waiting. It'll totally be worth it though!",
        "Still waiting... you're probably tired from all those jumping jacks.  Feel free to take a rest...",
        "Still waiting... did you fall asleep?",
        "Still waiting... maybe the network fell asleep too!",
        "Still waiting... hmm, network conditions must be unusually busy",
        "Still waiting... ok now even I'm growing impatient!",
    ]
    for i in range(100):
        #print(f"[DEBUG] ==== starting poll iteration {i+1} ====")
        try:
            r = requests.get(status_url, timeout=10)
            #print(f"[DEBUG] poll {i+1}: HTTP {r.status_code}")
            if r.status_code == 200:
                # Gateway now returns the full TX once it’s been seen on-chain.
                print(f"Authorization Tx ID: {tx.id}")
                print("   Authorized on-chain.")
                time.sleep(10)
                return 0, tx.id
            #elif r.status_code == 404:
            #elif r.status_code == 202:
            elif r.status_code in (202, 404):
                # Still pending
                #print(f"[DEBUG] status pending (404)")
                pass
            else:
                # Something weird happened
                print(f"[DEBUG] unexpected HTTP status: {r.status_code}, content: {r.text}")
        #except Exception as e:
             #print(f"[DEBUG] poll {i+1} exception: {e}")
        except Exception:
            pass

        # Every 12 iterations (12 x 5s = 60s), print the next "waiting" message (wrap around if needed)
        if i > 0 and i % 12 == 0:
            idx = ((i // 12) - 1) % len(tidbits)
            print(tidbits[idx])
        #print(f"[DEBUG] Sleeping for 5s before next poll") 
        time.sleep(5)

    print(f"[WARNING] I give up!  Transaction still pending, but you can check later here:")
    print(f"          {status_url}")
    return 1, None
