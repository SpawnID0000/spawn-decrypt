# src/spawn_decrypt/gui.py
"""
Simple Tkinter GUI for Spawn Tools (Authorize and Decrypt)
Persists fields across sessions in settings.env
"""
import os, io, sys
import threading
import tkinter as tk
import time
import json
import requests
import base64
import concurrent.futures
import contextlib

from tkinter import ttk, filedialog
from pathlib import Path
from PIL import Image, ImageTk

from dotenv import load_dotenv, set_key
from .author import authorize, compute_arweave_address
from .decrypt import decrypt_asset
from .wallet_gen import save_wallet_jwk
from requests.exceptions import JSONDecodeError

def sync_remote_directory(owner: str, repo: str, branch: str, subdir: str, local_dir: Path):
    """
    Syncs everything under:
      https://api.github.com/repos/{owner}/{repo}/contents/{subdir}?ref={branch}
    down into local_dir, only grabbing files that aren’t already present locally.

    owner/repo/branch/subdir examples for your case:
      owner = "SpawnID0000"
      repo  = "spawn-decrypt"
      branch = "main"
      subdir  = "src/spawn_decrypt/said"   (or "src/spawn_decrypt/jspf")

    local_dir should be Path(__file__).parent / "said"  (or / "jspf").
    """
    # 1) Call GitHub Contents API
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{subdir}"
    params = {"ref": branch}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"[sync] Failed to list {subdir} on GitHub: {e}")
        return

    remote_items = r.json()  # a list of dicts, each with 'name', 'type', 'download_url', etc.

    # Ensure local_dir exists
    local_dir.mkdir(parents=True, exist_ok=True)

    # 2) Build a set of local filenames (just the base names)
    existing = {f.name for f in local_dir.glob("*") if f.is_file()}

    for item in remote_items:
        if item.get("type") != "file":
            continue
        fname = item.get("name", "")
        if not fname.endswith((".said", ".jspf")):
            continue

        if fname not in existing:
            # 3) Download it
            dl_url = item.get("download_url")
            if not dl_url:
                continue
            try:
                resp = requests.get(dl_url, timeout=10)
                resp.raise_for_status()
            except Exception as e:
                print(f"[sync] Failed to download {fname}: {e}")
                continue

            dest = local_dir / fname
            with open(dest, "wb") as out_f:
                out_f.write(resp.content)
            print(f"[sync] Pulled new file: {fname}")

class GuiStdout:
    """File-like stdout that sends each line to self._log immediately."""
    def __init__(self, log_func, *, suppress_authorized: bool = False):
        self.log = log_func
        self._buf = ""
        self.suppress_authorized = suppress_authorized

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            # only filter this line if flag is set
            if self.suppress_authorized and "already authorized in TX" in line:
                continue
            self.log(line)

    def flush(self):
        pass


def run_in_thread(fn, callback, *args, **kwargs):
    """
    Helper to run a function in a background thread and optionally call a callback with its result.
    """
    def _worker():
        try:
            result = fn(*args, **kwargs)
            if callback:
                kwargs.get('self').after(0, lambda: callback(result))
        except Exception as e:
            if callback:
                kwargs.get('self').after(0, lambda: callback(1, str(e)))
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


class SpawnGUI(tk.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title("SpawnStore")
        self.geometry("850x500")
        self.minsize(850, 500)

        # === Sync new .said and .jspf from GitHub ===
        base = Path(__file__).parent
        # Local directories (where gui.py expects to find said/ and jspf/)
        said_local = base / "said"
        jspf_local = base / "jspf"

        # GitHub repo info
        owner  = "SpawnID0000"
        repo   = "spawn-decrypt"
        branch = "main"

        # Remote subdirs inside the GitHub repo
        said_subdir = "src/spawn_decrypt/said"
        jspf_subdir = "src/spawn_decrypt/jspf"

        # Sync both directories
        sync_remote_directory(owner, repo, branch, said_subdir, said_local)
        sync_remote_directory(owner, repo, branch, jspf_subdir, jspf_local)

        # Setup settings.env in the package directory (creates file if missing)
        self.env_path = Path(__file__).parent / "settings.env"
        self.env_path.touch(exist_ok=True)
        load_dotenv(dotenv_path=self.env_path)

        # Top container for tabs and wallet generation
        top_frame = ttk.Frame(self)
        top_frame.pack(fill='x', padx=5, pady=5)

        # Notebook for tabs
        self.notebook = ttk.Notebook(top_frame)
        self.notebook.pack(side='left', fill='x', expand=True)

        # Main Frame tab
        self.main_frame = ttk.Frame(self.notebook)
        self._build_main_frame_tab(self.main_frame)
        self.notebook.add(self.main_frame, text="Main Frame")

        # Authorize tab
        self.auth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.auth_frame, text="Authorize")
        self._build_authorize_tab(self.auth_frame)

        # Decrypt tab
        self.dec_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dec_frame, text="Decrypt")
        self._build_decrypt_tab(self.dec_frame)

        # —————————————————————————————————————————————
        # Sync “Source” field both ways between Main Frame ↔ Authorize ↔ Decrypt
        # main_source → authorize.tab.contract_var & decrypt.tab.source_var
        self.main_source_var.trace_add("write",
            lambda *a: self.contract_var.set(self.main_source_var.get()))
        self.main_source_var.trace_add("write",
            lambda *a: self.source_var.set(self.main_source_var.get()))

        # authorize.tab.contract_var → main_source
        self.contract_var.trace_add("write",
            lambda *a: self.main_source_var.set(self.contract_var.get()))
        # decrypt.tab.source_var → main_source
        self.source_var.trace_add("write",
            lambda *a: self.main_source_var.set(self.source_var.get()))
        # —————————————————————————————————————————————

        # # --- Log canvas with centered background image ---
        # # Load image relative to this file
        # img_path = Path(__file__).parent / "logo.png"
        # img = Image.open(img_path).convert("RGBA")
        # opacity = 0.1
        # white_bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
        # blended = Image.blend(white_bg, img, opacity)
        # self._log_bg = ImageTk.PhotoImage(blended)

        # # Canvas for background + text, with vertical scrollbar
        # self.log_canvas = tk.Canvas(self, highlightthickness=0)
        # # image centered
        # #self._log_img_id = self.log_canvas.create_image(0, 0, image=self._log_bg, anchor="center")
        # # anchored to the top
        # self._log_img_id = self.log_canvas.create_image(0, 0, image=self._log_bg, anchor="n")


        # # Scrollbar
        # vsb = ttk.Scrollbar(self, orient="vertical", command=self.log_canvas.yview)
        # self.log_canvas.configure(yscrollcommand=vsb.set)

        # # Pack canvas + scrollbar
        # self.log_canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        # vsb.pack(side="right", fill="y", pady=5)

        # # Reposition the image on resize
        # self.log_canvas.bind('<Configure>', lambda evt: self._on_log_resize(evt))
        # self._log_y = 10

        # whenever main_source_var changes, push its value into contract_var (Authorize tab)
        #self.main_source_var.trace_add("write", lambda *a: self.contract_var.set(self.main_source_var.get()))
        # and into source_var (Decrypt tab)
        #self.main_source_var.trace_add("write", lambda *a: self.source_var.set(self.main_source_var.get()))

        # Text widget for log output
        self.log_text = tk.Text(
            self,
            wrap="none",
            state="disabled",        # start read-only
            font=("TkDefaultFont", 10)
        )
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=vsb.set)
        self.log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        vsb.pack(side="right", fill="y", pady=5)

        # Load SAID metadata (artists/tracks)
        self._load_said_metadata()
        # Load JSPF metadata (albums)
        self._load_jspf_metadata()
        # Add dropdowns: Artist, Album, Track
        self._add_dropdowns(self.main_frame)

    def _on_log_resize(self, event):
        """
        Re-center the background image whenever the canvas is resized.
        """
        # event.width and event.height are the new canvas size
        #cx, cy = event.width / 2, event.height / 2
        #self.log_canvas.coords(self._log_img_id, cx, cy)

        img_w = self._log_bg.width()
        img_h = self._log_bg.height()
        canvas_w, canvas_h = event.width, event.height

        # center horizontally always
        cx = canvas_w / 2
        # if canvas is taller than image, center vertically; else pin top
        if canvas_h > img_h:
            cy = canvas_h / 2
        else:
            cy = 0

        self.log_canvas.coords(self._log_img_id, cx, cy)

        # cx = event.width / 2  # center horizontally
        # cy=0 # to keep the image top flush with the canvas top
        # self.log_canvas.coords(self._log_img_id, cx, 0)

    def _log(self, msg: str):
        # # draw text on the canvas over the background
        # self.log_canvas.create_text(
        #     10, self._log_y,
        #     anchor="nw",
        #     text=msg,
        #     fill="black",
        #     font=("TkDefaultFont", 10)
        # )
        # self._log_y += 18  # line spacing
        # # expand scrollregion if needed
        # self.log_canvas.configure(scrollregion=self.log_canvas.bbox("all"))

        # Replace high Unicode chars (emoji, etc.) with '?'
        safe_msg = ''.join(c if ord(c) < 128 else ' :)  ' for c in msg)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", safe_msg + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _build_main_frame_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(4, weight=1)

        # Output Location
        self.main_output_dir_var = tk.StringVar()
        self.main_output_dir_var.set(os.getenv("OUTPUT_DIR", ""))
        self.main_output_dir_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "OUTPUT_DIR", self.main_output_dir_var.get())
        )
        ttk.Label(parent, text="Output Location:").grid(row=0, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.main_output_dir_var, width=50).grid(row=0, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_output_dir).grid(row=0, column=3, sticky="w")

        # Wallet JSON
        self.main_wallet_var = tk.StringVar()
        self.main_wallet_var.set(os.getenv("DEC_WALLET", ""))
        self.main_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "DEC_WALLET", self.main_wallet_var.get())
        )
        ttk.Label(parent, text="Wallet JSON:").grid(row=1, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.main_wallet_var, width=50).grid(row=1, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_dec_wallet).grid(row=1, column=3, sticky="w")

        # Source (contract TX ID or .spwn/.said file path)
        self.main_source_var = tk.StringVar()
        self.main_source_var.set(os.getenv("SOURCE", ""))
        self.main_source_var.trace_add("write", lambda *a: set_key(str(self.env_path), "SOURCE", self.main_source_var.get()))
        ttk.Label(parent, text="Source (SPWN, SAID, or TX ID):").grid(row=2, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.main_source_var, width=50).grid(row=2, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_source).grid(row=2, column=3, sticky="w")

        # Spacer + optional header
        parent.grid_rowconfigure(3, minsize=15)
        #ttk.Label(parent, text="Optional settings:", foreground="gray").grid(row=4, column=1, columnspan=3, pady=(0,5))

        # Generate Wallet + Go Go Gadget
        # store a reference so we can hide/show it
        self.gen_main_btn = ttk.Button(parent, text="Generate Wallet", command=self._on_generate_wallet)
        self.gen_main_btn.grid(row=5, column=1, sticky="w", pady=10)
        ttk.Button(parent, text="Go Go Gadget", command=self._on_go_gadget)\
            .grid(row=5, column=2, pady=10, sticky="w", padx=(150, 0))
        # hide/show based on main_wallet_var
        def _toggle_main_btn(*_):
            if self.main_wallet_var.get():
                self.gen_main_btn.grid_remove()
            else:
                self.gen_main_btn.grid()
        # initial toggle
        _toggle_main_btn()
        # on change
        self.main_wallet_var.trace_add("write", _toggle_main_btn)

    def _build_authorize_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(4, weight=1)

        # --- Required settings ---
        # New User Wallet JSON
        self.new_wallet_var = tk.StringVar()
        self.new_wallet_var.set(os.getenv("NEW_USER_WALLET", ""))
        self.new_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "NEW_USER_WALLET", self.new_wallet_var.get())
        )
        ttk.Label(parent, text="New User Wallet JSON:").grid(row=0, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.new_wallet_var, width=50).grid(row=0, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_new_user).grid(row=0, column=3, sticky="w")

        # Source (SPWN, SAID, or TX ID)
        self.contract_var = tk.StringVar()
        self.contract_var.set(os.getenv("CONTRACT_OR_SPWN", ""))
        self.contract_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "CONTRACT_OR_SPWN", self.contract_var.get())
        )
        ttk.Label(parent, text="Source (SPWN, SAID, or TX ID):").grid(row=1, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.contract_var, width=50).grid(row=1, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_contract).grid(row=1, column=3, sticky="w")

        # Spacer + optional header
        parent.grid_rowconfigure(2, minsize=15)
        ttk.Label(parent, text="Optional settings:", foreground="gray").grid(row=3, column=1, columnspan=3, pady=(0,5))

        # Wrapped Key File
        self.keyfile_var = tk.StringVar()
        self.keyfile_var.set(os.getenv("KEY_FILE", ""))
        self.keyfile_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "KEY_FILE", self.keyfile_var.get())
        )
        ttk.Label(parent, text="Wrapped Key File:").grid(row=4, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.keyfile_var, width=50).grid(row=4, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_keyfile).grid(row=4, column=3, sticky="w")

        # Authorized Wallet JSON (optional)
        self.caller_wallet_var = tk.StringVar()
        self.caller_wallet_var.set(os.getenv("CALLER_WALLET", ""))
        self.caller_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "CALLER_WALLET", self.caller_wallet_var.get())
        )
        ttk.Label(parent, text="Authorized Wallet JSON:").grid(row=5, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.caller_wallet_var, width=50).grid(row=5, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_caller).grid(row=5, column=3, sticky="w")

        # Authorize + Wallet buttons
        ttk.Button(parent, text="Authorize", command=self._on_authorize) \
            .grid(row=6, column=2, pady=10, sticky="w", padx=(150, 0))
        # store a reference so we can hide/show it
        self.gen_auth_btn = ttk.Button(parent, text="Generate Wallet", command=self._on_generate_wallet)
        self.gen_auth_btn.grid(row=6, column=1, sticky="w", pady=10)

        # hide/show based on new_wallet_var
        def _toggle_auth_btn(*_):
            if self.new_wallet_var.get():
                self.gen_auth_btn.grid_remove()
            else:
                self.gen_auth_btn.grid()
        # initial
        _toggle_auth_btn()
        # on change
        self.new_wallet_var.trace_add("write", _toggle_auth_btn)

    def _build_decrypt_tab(self, parent):
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(4, weight=1)

        # Output Location
        self.output_dir_var = tk.StringVar()
        self.output_dir_var.set(os.getenv("OUTPUT_DIR", ""))
        self.output_dir_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "OUTPUT_DIR", self.output_dir_var.get())
        )
        ttk.Label(parent, text="Output Location:").grid(row=0, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.output_dir_var, width=50).grid(row=0, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_output_dir).grid(row=0, column=3, sticky="w")

        # Wallet JSON
        self.dec_wallet_var = tk.StringVar()
        self.dec_wallet_var.set(os.getenv("DEC_WALLET", ""))
        self.dec_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "DEC_WALLET", self.dec_wallet_var.get())
        )
        ttk.Label(parent, text="Wallet JSON:").grid(row=1, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.dec_wallet_var, width=50).grid(row=1, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_dec_wallet).grid(row=1, column=3, sticky="w")

        # Source (SPWN, SAID, or TX ID)
        self.source_var = tk.StringVar()
        self.source_var.set(os.getenv("SOURCE", ""))
        self.source_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "SOURCE", self.source_var.get())
        )
        ttk.Label(parent, text="Source (SPWN, SAID, or TX ID):").grid(row=2, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.source_var, width=50).grid(row=2, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_source).grid(row=2, column=3, sticky="w")

        # Spacer + optional header
        parent.grid_rowconfigure(3, minsize=15)
        ttk.Label(parent, text="Optional settings:", foreground="gray").grid(row=4, column=1, columnspan=3, pady=(0,5))

        # Wrapped Key File
        self.dec_keyfile_var = tk.StringVar()
        self.dec_keyfile_var.set(os.getenv("DEC_KEY_FILE", ""))
        self.dec_keyfile_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "DEC_KEY_FILE", self.dec_keyfile_var.get())
        )
        ttk.Label(parent, text="Wrapped Key File:").grid(row=5, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.dec_keyfile_var, width=50).grid(row=5, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_dec_keyfile).grid(row=5, column=3, sticky="w")

        # Auth TX ID (override)
        self.auth_tx_var = tk.StringVar()
        self.auth_tx_var.set(os.getenv("AUTH_TX", ""))
        self.auth_tx_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "AUTH_TX", self.auth_tx_var.get())
        )
        ttk.Label(parent, text="Auth TX ID (override):").grid(row=6, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.auth_tx_var, width=50).grid(row=6, column=2)

        # Decrypt + Wallet buttons
        ttk.Button(parent, text="Decrypt", command=self._on_decrypt) \
            .grid(row=7, column=2, pady=10, sticky="w", padx=(150, 0))
        # store a reference so we can hide/show it
        self.gen_dec_btn = ttk.Button(parent, text="Generate Wallet", command=self._on_generate_wallet)
        self.gen_dec_btn.grid(row=7, column=1,  sticky="w", pady=10)

        # hide/show based on dec_wallet_var
        def _toggle_dec_btn(*_):
            if self.dec_wallet_var.get():
                self.gen_dec_btn.grid_remove()
            else:
                self.gen_dec_btn.grid()
        # initial
        _toggle_dec_btn()
        # on change
        self.dec_wallet_var.trace_add("write", _toggle_dec_btn)

    # Browse handlers
    def _browse_caller(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"), ("All files","*")])
        if path:
            self.caller_wallet_var.set(path)

    def _browse_new_user(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"), ("All files","*")])
        if path:
            self.new_wallet_var.set(path)

    def _browse_contract(self):
        path = filedialog.askopenfilename(
            filetypes=[
                ("SPWN package","*.spwn"),
                ("SAID file","*.said"),
                ("All files","*")
            ]
        )
        if not path:
            return

        if path.lower().endswith(".said"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    said = json.load(f)
                contx = said.get("contx_id")
                if contx:
                    # set both Main Frame & Decrypt tabs
                    self.source_var.set(contx)
                    self.main_source_var.set(contx)
                    return
                else:
                    self._log(f"[ERROR] SAID file has no contx_id field")
            except Exception as e:
                self._log(f"[ERROR] Failed to parse SAID file: {e}")

        # fallback: regular SPWN or TX ID path
        self.contract_var.set(path)

        if path:
            self.contract_var.set(path)

    def _browse_keyfile(self):
        path = filedialog.askopenfilename(filetypes=[("Wrapped key","*.*")])
        if path:
            self.keyfile_var.set(path)

    def _browse_output_dir(self):
        path = filedialog.askdirectory(
            title="Select output directory",
            mustexist=True
        )
        if path:
            self.output_dir_var.set(path)
            self.main_output_dir_var.set(path)

    def _browse_dec_wallet(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"), ("All files","*")])
        if path:
            self.dec_wallet_var.set(path)
            self.main_wallet_var.set(path)

    def _browse_source(self):
        path = filedialog.askopenfilename(
            filetypes=[
                ("SPWN package","*.spwn"),
                ("SAID file","*.said"),
                ("All files","*")
            ]
        )
        if not path:
            return

        if path.lower().endswith(".said"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    said = json.load(f)
                contx = said.get("contx_id")
                if contx:
                    # set both Main Frame & Decrypt tabs
                    self.source_var.set(contx)
                    self.main_source_var.set(contx)
                    return
                else:
                    self._log(f"[ERROR] SAID file has no contx_id field")
            except Exception as e:
                self._log(f"[ERROR] Failed to parse SAID file: {e}")

        # fallback: regular SPWN or TX ID path
        self.source_var.set(path)
        self.main_source_var.set(path)

    def _browse_dec_keyfile(self):
        path = filedialog.askopenfilename(filetypes=[("Wrapped key","*.*")])
        if path:
            self.dec_keyfile_var.set(path)

    def _load_said_metadata(self):
        said_dir = Path(__file__).parent / "said"
        records = []
        for f in said_dir.glob("*.said"):
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass

        # build the mappings
        self.artist_to_tracks  = {}
        self.track_to_artist   = {}
        self.record_by_track   = {}
        self.record_by_spawnid = {}    # NEW

        for r in records:
            artist = r.get("artist")
            track  = r.get("trk_name")
            if artist and track:
                self.artist_to_tracks.setdefault(artist, []).append(track)
                self.track_to_artist[track] = artist
                self.record_by_track[track] = r

            # Collect any urn:spawnid:XXX identifiers
            for urn in r.get("identifier", []):
                if urn.startswith("urn:spawnid:"):
                    spawnid = urn.split(":", 2)[-1]
                    self.record_by_spawnid[spawnid] = r

        # sort each list
        for a in self.artist_to_tracks:
            self.artist_to_tracks[a].sort()

        # remember full sorted lists too
        self.all_artists = sorted(self.artist_to_tracks.keys())
        self.all_tracks  = sorted(self.track_to_artist.keys())

    def _load_jspf_metadata(self):
        """
        Scan the `jspf` directory for .jspf files, parse each,
        and index albums by artist for dropdown population.
        """
        jspf_dir = Path(__file__).parent / "jspf"
        self.jspf_records = []
        self.albums_by_artist = {}

        if jspf_dir.exists():
            for f in jspf_dir.glob("*.jspf"):
                try:
                    raw = f.read_text(encoding="utf-8")
                    data = json.loads(raw)
                    pl = data.get("playlist", {})
                    artist = pl.get("creator", "")
                    album  = pl.get("title", "")
                    if not artist or not album:
                        continue

                    # keep full record for lookups later
                    self.jspf_records.append({
                        "artist": artist,
                        "album":  album,
                        "file":   f
                    })

                    # index albums by artist
                    self.albums_by_artist.setdefault(artist, []).append(album)

                except Exception:
                    # skip malformed files
                    continue

        # sort each artist’s album list
        for art in self.albums_by_artist:
            self.albums_by_artist[art].sort()

        # full list of artists (for initial Artist dropdown)
        self.all_jspf_artists = sorted(self.albums_by_artist.keys())

        # full list of albums (for initial Album dropdown)
        self.all_jspf_albums = sorted({
            rec["album"]
            for rec in self.jspf_records
        })


    def _add_dropdowns(self, parent):
        """
        Add Artist, Album, and Track dropdowns to the given parent frame.
        """
        # Artist combo (row 8)
        ttk.Label(parent, text="Artist:")\
            .grid(row=8, column=1, sticky="e", padx=5, pady=5)
        self.artist_var = tk.StringVar()

        # Combine JSPF artists and SAID artists into one sorted list:
        combined_artists = sorted(
           set(self.all_jspf_artists) | set(self.all_artists)
        )
        self.artist_cb = ttk.Combobox(
           parent,
           textvariable=self.artist_var,
           values=combined_artists,
           state="readonly",
           width=50
        )
        self.artist_cb.grid(row=8, column=2, sticky="w")
        self.artist_cb.bind("<<ComboboxSelected>>", self._on_artist_selected)

        # Album combo (row 9)
        ttk.Label(parent, text="Album:")\
            .grid(row=9, column=1, sticky="e", padx=5, pady=5)
        self.album_var = tk.StringVar()
        self.album_cb = ttk.Combobox(
            parent,
            textvariable=self.album_var,
            values=self.all_jspf_albums,
            state="readonly",
            width=50
        )
        self.album_cb.grid(row=9, column=2, sticky="w")
        self.album_cb.bind("<<ComboboxSelected>>", self._on_album_selected)

        # Track combo (row 10)
        ttk.Label(parent, text="Track:")\
            .grid(row=10, column=1, sticky="e", padx=5, pady=5)
        self.track_var = tk.StringVar()
        self.track_cb = ttk.Combobox(
            parent,
            textvariable=self.track_var,
            values=self.all_tracks,
            state="readonly",
            width=50
        )
        self.track_cb.grid(row=10, column=2, sticky="w")
        self.track_cb.bind("<<ComboboxSelected>>", self._on_track_selected)

        # Price display (AR + USD)
        self.price_var = tk.StringVar(value="–")
        tk.Label(self.main_frame, text="Price:")\
            .grid(row=11, column=2, sticky="w", padx=15, pady=(0,10))
        self.price_entry = tk.Entry(
            self.main_frame,
            textvariable=self.price_var,
            state="readonly",
            width=30
        )
        self.price_entry.grid(row=11, column=2, columnspan=2, sticky="w", padx=75, pady=(0,10))

    def _update_price_display(self):
        """
        Build the list of contract IDs (txids) either
        from the currently selected album’s tracks, or
        from the single-track Source box, then spawn
        a background thread to fetch & sum their prices.
        """
        # 1) Gather txids
        txids = []
        if self.album_var.get():
            # album mode: each track entry in current_album_record["tracks"]
            for tr in self.current_album_record.get("tracks", []):
                # JSPF track objects usually put the tx in "identifier"
                cid = tr.get("identifier") or tr.get("contx_id")
                if cid:
                    txids.append(cid)
        else:
            # single‐track mode: whatever’s in the Source field
            src = self.source_var.get().strip()
            if src:
                txids = [src]

        # 2) Fire off the fetch/sum in a daemon thread
        threading.Thread(
            target=self._fetch_and_set_price,
            args=(txids,),
            daemon=True
        ).start()

    def _on_artist_selected(self, evt):
        """
        When an artist is picked, populate the Album dropdown
        with that artist’s albums, then clear any Track selection.
        """

        artist = self.artist_var.get()

        # Filter albums for this artist
        albums = self.albums_by_artist.get(artist, [])
        self.album_cb.configure(values=albums)
        if albums:
            # Auto‐select the first album
            self.album_var.set(albums[0])
            # Clear any existing Track selection; actual track list will be populated in _on_album_selected
            self.track_cb.configure(values=[])
            self.track_var.set("")
            # Immediately trigger album‐selected logic so Price updates without extra click
            self._on_album_selected(None)
        else:
            # No JSPF albums: clear album selection and show only this artist’s SAID tracks
            self.album_var.set("")
            said_tracks = self.artist_to_tracks.get(artist, [])
            self.track_cb.configure(values=said_tracks)
            self.track_var.set("")

        # Clear any existing Track selection
        self.track_var.set("")

    def _on_album_selected(self, evt):
        """
        When an album is selected, sync the artist dropdown and update
        the Track dropdown options—but leave the Track selection blank.
        """

        album = self.album_var.get()

        # Find the matching JSPF record
        rec = next(
            (r for r in self.jspf_records
             if r["album"] == album),
             #if r["album"] == album and r["artist"] == artist),
            None
        )

        # Sync artist & build list of tracks for this album
        if rec:
            # Ensure the artist dropdown stays in sync
            self.artist_var.set(rec["artist"])

            # Load the list of track titles from the JSPF file
            try:
                data = json.loads(rec["file"].read_text(encoding="utf-8"))
                tracks = [
                    t.get("title", "")
                    for t in data.get("playlist", {}).get("track", [])
                ]
            except Exception:
                tracks = []
            rec["tracks"] = data.get("playlist", {}).get("track", [])
            self.current_album_record = rec
        else:
            # Fallback: if no JSPF match, show all SAID-based tracks
            tracks = self.all_tracks
            self.current_album_record = {"tracks": []}

        # Populate the Track combobox with the new options, but clear any current selection
        self.track_cb.configure(values=tracks)
        self.track_var.set("")
        # refresh price display whenever track or album changes
        self._update_price_display()

    def _on_track_selected(self, evt):
        """
        When a track is selected:
        - Sync the Artist dropdown
        - Clear the Album dropdown (only one of Album/Track may be active)
        - Update the Source from the SAID record
        """

        track = self.track_var.get()
        # Sync artist
        artist = self.track_to_artist.get(track)
        if artist:
            self.artist_var.set(artist)
        # Clear any Album selection
        self.album_var.set("")
        # Sync source context ID
        rec = self.record_by_track.get(track)
        if rec and "contx_id" in rec:
            cid = rec["contx_id"]
            self.main_source_var.set(cid)
            self.source_var.set(cid)
            # to also use it in the Authorize tab:
            self.contract_var.set(cid)
        # refresh price display whenever track or album changes
        self._update_price_display()


    # Button callbacks
    def _on_go_gadget(self):
        """Authorize then decrypt in sequence."""
        #self._log("Go Go Gadget...")
        if self.album_var.get():
            threading.Thread(target=self._go_gadget_album, daemon=True).start()
        else:
            threading.Thread(target=self._go_gadget_track, daemon=True).start()
        #threading.Thread(target=self._do_go_gadget, daemon=True).start()

    def _go_gadget_track(self):
        """
        Authorize + decrypt a single selected track (exactly your old _do_go_gadget behavior).
        """
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = GuiStdout(self._log)
        sys.stderr = GuiStdout(self._log)
        try:
            # Sync Main Frame → Authorize-tab inputs for this track
            self.new_wallet_var.set(self.main_wallet_var.get())
            self.contract_var.set(self.main_source_var.get())

            # 1) Loop until authorization succeeds
            auth_tx = None
            self._log(f"Starting authorization")
            for attempt in range(1, 1000):
                if attempt > 1:
                    self._log(f"Authorizing track (attempt {attempt})")
                code, txid = authorize(
                    caller_wallet   = self.caller_wallet_var.get() or None,
                    new_user_wallet = self.new_wallet_var.get(),
                    contract_or_spwn= self.contract_var.get(),
                    key_file        = self.keyfile_var.get() or None
                )
                if code == 0:
                    self._log("Authorization confirmed\n")
                    auth_tx = txid or auth_tx
                    break
                self._log("Authorization pending; retrying in 10 seconds")
                time.sleep(10)

            # 2) Poll gateway → GraphQL for wrappedKey
            jwk       = json.load(open(self.new_wallet_var.get(), 'r', encoding='utf-8'))
            user_addr = compute_arweave_address(jwk)
            contract_tx = self.contract_var.get()
            if auth_tx:
                self._log("Fetching wrappedKey from gateway")
                for i in range(60):
                    try:
                        r = requests.get(f"https://arweave.net/tx/{auth_tx}/data", timeout=5)
                        r.raise_for_status()
                        try:
                            payload = r.json()
                        except ValueError:
                            raw = r.content
                            pad = b"=" * ((4 - len(raw) % 4) % 4)
                            payload = json.loads(base64.urlsafe_b64decode(raw + pad))
                        if payload.get("wrappedKey"):
                            self._log("WrappedKey found; ready to decrypt")
                            break
                    except Exception as e:
                        self._log(f"[DEBUG] gateway fetch error: {e}")
                    time.sleep(5)
                else:
                    self._log("[WARNING] Gateway did not return wrappedKey in time; falling back to GraphQL")
                    gql = {
                        "query": f"""
                        {{
                          transactions(
                            tags: [
                              {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
                              {{ name: "Contract",  values: ["{contract_tx}"] }},
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
                    for j in range(36):
                        self._log(f"GraphQL fetch attempt {j+1}/36")
                        try:
                            resp = requests.post("https://arweave.net/graphql", json=gql, timeout=5)
                            resp.raise_for_status()
                            edges = resp.json()["data"]["transactions"]["edges"]
                            if edges:
                                new_tx = edges[0]["node"]["id"]
                                auth_tx = new_tx
                                self._log(f"Found authorize TX {new_tx} via GraphQL; ready to decrypt")
                                break
                        except Exception as e:
                            self._log(f"[DEBUG] GraphQL fetch error: {e}")
                        time.sleep(5)
                    else:
                        self._log("[WARNING] GraphQL indexer did not catch up; proceeding anyway")

            # 3) Decrypt that single track
            self._log("Starting decryption")
            decrypt_asset(
                wallet_file = self.main_wallet_var.get(),
                source      = self.main_source_var.get(),
                key_file    = None,
                auth_tx     = auth_tx,
                output_dir  = self.main_output_dir_var.get()
            )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

    def _find_auth_tx_for(self, contract_tx: str) -> str | None:
        """
        If authorize() returned no new TX (pre-authorized case),
        query Arweave GraphQL for an existing authorize interaction.
        """
        jwk       = json.load(open(self.new_wallet_var.get(), 'r', encoding='utf-8'))
        user_addr = compute_arweave_address(jwk)
        gql = {
            "query": f"""
            {{
              transactions(
                tags: [
                  {{ name: "App-Name",  values: ["SmartWeaveAction"] }},
                  {{ name: "Contract",  values: ["{contract_tx}"] }},
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
        for i in range(36):  # ~3 minutes
            try:
                resp = requests.post("https://arweave.net/graphql", json=gql, timeout=5)
                resp.raise_for_status()
                edges = resp.json()["data"]["transactions"]["edges"]
                if edges:
                    return edges[0]["node"]["id"]
            except Exception:
                pass
            time.sleep(5)
        return None

    def _go_gadget_album(self):
        """
        Authorize & decrypt every track in the selected album,
        doing all authorize() calls in parallel but silencing
        their own printouts so only our parallel thread messages appear.
        """
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = GuiStdout(self._log, suppress_authorized=True)
        sys.stderr = GuiStdout(self._log, suppress_authorized=True)

        try:
            # 1) Find JSPF record
            album = self.album_var.get()
            jspf_rec = next((r for r in self.jspf_records if r["album"] == album), None)
            if not jspf_rec:
                self._log(f"[ERROR] No JSPF metadata for album '{album}'")
                return

            # 2) Parse out the tracks list and extract each contract_id
            playlist = json.loads(jspf_rec["file"].read_text(encoding="utf-8"))["playlist"]
            contract_ids = []
            for t in playlist.get("track", []):
                ext = t.get("extension", {})
                contracts = ext.get("urn:spawnSPF:contract", [])
                url = contracts[0] if contracts else None
                if not url:
                    self._log("[WARNING] no contract TX in extension; skipping track")
                    continue
                cid = url.rsplit("/",1)[-1] if url.startswith("https://arweave.net/") else url
                contract_ids.append(cid)

            if not contract_ids:
                self._log("[ERROR] No contract IDs found; aborting album flow")
                return

            # 3) Authorize all contract_ids in parallel
            self._log(f"Submitting {len(contract_ids)} authorizations in parallel")
            auth_map: dict[str,str] = {}

            def _auth_contract(cid):
                self._log(f"Starting authorization for {cid}")
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    code, txid = authorize(
                        caller_wallet   = self.caller_wallet_var.get() or None,
                        new_user_wallet = self.new_wallet_var.get(),
                        contract_or_spwn= cid,
                        key_file        = self.keyfile_var.get() or None
                    )
                return cid, code, txid
            self._log(f"")

            with concurrent.futures.ThreadPoolExecutor(max_workers=len(contract_ids)) as pool:
                futures = { pool.submit(_auth_contract, cid): cid for cid in contract_ids }
                for fut in concurrent.futures.as_completed(futures):
                    cid = futures[fut]
                    try:
                        contract_id, code, auth_tx = fut.result()
                        if code != 0:
                            self._log(f"[ERROR] Authorization failed for {contract_id} (code {code})")
                            continue
                        if auth_tx:
                            # fresh authorization
                            auth_map[contract_id] = auth_tx
                            self._log(f"Authorization confirmed for {contract_id} - auth TX {auth_tx}")
                        else:
                            # already pre-authorized; find the existing TX
                            found = self._find_auth_tx_for(contract_id)
                            if found:
                                auth_map[contract_id] = found
                                self._log(f"Pre-authorized {contract_id} - existing auth TX {found}")
                            else:
                                self._log(f"[ERROR] No authorize interaction found for pre-authorized {contract_id}")
                    except Exception as e:
                        self._log(f"[ERROR] Exception in authorization thread for {cid}: {e}")

            if not auth_map:
                self._log("[ERROR] No successful authorizations; aborting album flow")
                return

            self._log(f"")

            # 4) Poll each auth_TX for wrappedKey
            for contract_id, auth_tx in auth_map.items():
                self._log(f"Waiting for wrappedKey (auth TX {auth_tx}) for contract {contract_id}")
                for i in range(60):
                    try:
                        r = requests.get(f"https://arweave.net/tx/{auth_tx}/data", timeout=5)
                        r.raise_for_status()
                        try:
                            payload = r.json()
                        except ValueError:
                            raw = r.content
                            pad = b"=" * ((4 - len(raw) % 4) % 4)
                            payload = json.loads(base64.urlsafe_b64decode(raw + pad))
                        if payload.get("wrappedKey"):
                            self._log(f"   wrappedKey found for {contract_id}")
                            break
                    except Exception as e:
                        self._log(f"[DEBUG] gateway error for {contract_id}: {e}")
                    time.sleep(5)
                else:
                    self._log(f"[WARNING] wrappedKey timeout for {contract_id} (proceeding)")
            self._log(f"")

            # 5) Decrypt each contract (track) one by one
            for contract_id, auth_tx in auth_map.items():
                self._log(f"Decrypting contract {contract_id}")
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                    decrypt_asset(
                        wallet_file = self.main_wallet_var.get(),
                        source      = contract_id,
                        key_file    = None,
                        auth_tx     = auth_tx,
                        output_dir  = self.main_output_dir_var.get()
                    )
                for line in buf.getvalue().splitlines():
                    self._log(line)

        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

    def _on_authorize(self):
        self._log("Starting authorization...")
        threading.Thread(target=self._do_authorize, daemon=True).start()

    def _do_authorize(self):
        old_stdout = sys.stdout
        sys.stdout = GuiStdout(self._log)
        try:
            code, txid = authorize(
                caller_wallet   = self.caller_wallet_var.get() or None,
                new_user_wallet = self.new_wallet_var.get(),
                contract_or_spwn= self.contract_var.get(),
                key_file        = self.keyfile_var.get() or None
            )
            if code == 0:
                self._log("   Authorization confirmed\n")
                if txid:
                    self._log(f"   New authorize TX ID: {txid}")
                else:
                    #self._log("   Already pre-authorized; no new TX.")
                    pass
            else:
                self._log(f"   Authorization failed (exit code {code})")
        except Exception as e:
            self._log(f"[ERROR] Exception in authorize(): {e}")
        finally:
            sys.stdout = old_stdout

    def _on_decrypt(self):
        self._log("\nStarting decryption...")
        threading.Thread(target=self._do_decrypt, daemon=True).start()

    def _do_decrypt(self):
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout = GuiStdout(self._log)
        sys.stderr = GuiStdout(self._log)
        try:
            code = decrypt_asset(
                wallet_file = self.dec_wallet_var.get(),
                source      = self.source_var.get(),
                key_file    = self.dec_keyfile_var.get() or None,
                auth_tx     = self.auth_tx_var.get() or None,
                output_dir  = self.output_dir_var.get() or None
            )
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr

    def _on_generate_wallet(self):
        """
        Generate a new wallet JSON and populate the active tab's wallet field.
        """
        path = save_wallet_jwk()
        self.new_wallet_var.set(path)
        self.dec_wallet_var.set(path)
        self.main_wallet_var.set(path)

    def _fetch_and_set_price(self, txids):
        total_winston = 0
        for txid in txids:
            # 1) fetch the tx JSON, skip on any decode/network error
            try:
                resp = requests.get(f"https://arweave.net/tx/{txid}?format=json", timeout=10)
                data = resp.json()
            except (requests.RequestException, JSONDecodeError):
                # could not fetch or parse JSON → skip this txid
                continue

            # 2) safely pull out the Init-State tag
            b64 = None
            for tag in data.get("tags", []):
                if tag.get("name") in ("Init-State", "QW5pdC1TdGF0ZQ"):
                    b64 = tag.get("value")
                    break
            if not b64:
                continue

            # 3) decode & parse JSON payload
            try:
                state = json.loads(base64.b64decode(b64))
            except Exception:
                continue

            # 4) accumulate the price
            total_winston += int(state.get("price", 0))

        # 5) convert winston → AR
        total_ar = total_winston / 1e12

        # 6) fetch AR→USD rate, skip on any error
        try:
            cg = requests.get(
                "https://api.coingecko.com/api/v3/simple/price",
                params={"ids": "arweave", "vs_currencies": "usd"},
                timeout=5
            ).json()
            rate = cg.get("arweave", {}).get("usd", 0)
        except (requests.RequestException, JSONDecodeError):
            rate = 0
        total_usd = total_ar * rate

        # 7) update the UI on the main thread
        disp = f"{total_ar:.6f} AR / ${total_usd:,.2f}"
        self.after(0, lambda: self.price_var.set(disp))

if __name__ == "__main__":
    app = SpawnGUI()
    app.mainloop()

def main():
    app = SpawnGUI()
    app.mainloop()