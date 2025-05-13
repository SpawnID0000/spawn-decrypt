# src/spawn_decrypt/gui.py
"""
Simple Tkinter GUI for Spawn Tools (Authorize and Decrypt)
Persists fields across sessions in settings.env
"""
import os, io, sys
import threading
import tkinter as tk

from tkinter import ttk, filedialog
from pathlib import Path
from PIL import Image, ImageTk

from dotenv import load_dotenv, set_key
from .author import authorize
from .decrypt import decrypt_asset


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
    def __init__(self):
        super().__init__()
        self.title("Spawn Decrypt GUI")
        self.geometry("800x500")
        self.minsize(800, 500)

        # Setup settings.env in the package directory (creates file if missing)
        self.env_path = Path(__file__).parent / "settings.env"
        self.env_path.touch(exist_ok=True)
        load_dotenv(dotenv_path=self.env_path)

        # Notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill='x', expand=False)

        # Authorize tab
        self.auth_frame = ttk.Frame(notebook)
        notebook.add(self.auth_frame, text="Authorize")
        self._build_authorize_tab(self.auth_frame)

        # Decrypt tab
        self.dec_frame = ttk.Frame(notebook)
        notebook.add(self.dec_frame, text="Decrypt")
        self._build_decrypt_tab(self.dec_frame)

        # --- Log canvas with centered background image ---
        # Load image relative to this file
        img_path = Path(__file__).parent / "logo.png"
        img = Image.open(img_path).convert("RGBA")
        opacity = 0.1
        white_bg = Image.new("RGBA", img.size, (255, 255, 255, 255))
        blended = Image.blend(white_bg, img, opacity)
        self._log_bg = ImageTk.PhotoImage(blended)

        # Canvas for background + text
        self.log_canvas = tk.Canvas(self, highlightthickness=0)
        # create the image item centered
        self._log_img_id = self.log_canvas.create_image(
            0, 0,
            image=self._log_bg,
            anchor="center"
        )
        self.log_canvas.pack(fill="both", expand=True, padx=5, pady=5)
        # reposition the image on resize
        self.log_canvas.bind('<Configure>', lambda evt: self._on_log_resize(evt))
        self._log_y = 10

    def _on_log_resize(self, event):
        """
        Re-center the background image whenever the canvas is resized.
        """
        # event.width and event.height are the new canvas size
        cx, cy = event.width / 2, event.height / 2
        self.log_canvas.coords(self._log_img_id, cx, cy)

    def _log(self, msg: str):
        # draw text on the canvas over the background
        self.log_canvas.create_text(
            10, self._log_y,
            anchor="nw",
            text=msg,
            fill="black",
            font=("TkDefaultFont", 10)
        )
        self._log_y += 18  # line spacing
        # expand scrollregion if needed
        self.log_canvas.configure(scrollregion=self.log_canvas.bbox("all"))

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
        ttk.Button(parent, text="Browse...", command=self._browse_new_user).grid(row=0, column=3)

        # Source (.spwn or TX ID)
        self.contract_var = tk.StringVar()
        self.contract_var.set(os.getenv("CONTRACT_OR_SPWN", ""))
        self.contract_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "CONTRACT_OR_SPWN", self.contract_var.get())
        )
        ttk.Label(parent, text="Source (.spwn or TX ID):").grid(row=1, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.contract_var, width=50).grid(row=1, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_contract).grid(row=1, column=3)

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
        ttk.Button(parent, text="Browse...", command=self._browse_keyfile).grid(row=4, column=3)

        # Authorized Wallet JSON (optional)
        self.caller_wallet_var = tk.StringVar()
        self.caller_wallet_var.set(os.getenv("CALLER_WALLET", ""))
        self.caller_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "CALLER_WALLET", self.caller_wallet_var.get())
        )
        ttk.Label(parent, text="Authorized Wallet JSON:").grid(row=5, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.caller_wallet_var, width=50).grid(row=5, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_caller).grid(row=5, column=3)

        # Run button
        ttk.Button(parent, text="Authorize", command=self._on_authorize).grid(row=6, column=2, pady=10)

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
        ttk.Button(parent, text="Browse...", command=self._browse_output_dir).grid(row=0, column=3)

        # Wallet JSON
        self.dec_wallet_var = tk.StringVar()
        self.dec_wallet_var.set(os.getenv("DEC_WALLET", ""))
        self.dec_wallet_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "DEC_WALLET", self.dec_wallet_var.get())
        )
        ttk.Label(parent, text="Wallet JSON:").grid(row=1, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.dec_wallet_var, width=50).grid(row=1, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_dec_wallet).grid(row=1, column=3)

        # Source (.spwn or TX ID)
        self.source_var = tk.StringVar()
        self.source_var.set(os.getenv("SOURCE", ""))
        self.source_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "SOURCE", self.source_var.get())
        )
        ttk.Label(parent, text="Source (.spwn or TX ID):").grid(row=2, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.source_var, width=50).grid(row=2, column=2)
        ttk.Button(parent, text="Browse...", command=self._browse_source).grid(row=2, column=3)

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
        ttk.Button(parent, text="Browse...", command=self._browse_dec_keyfile).grid(row=5, column=3)

        # Auth TX ID (override)
        self.auth_tx_var = tk.StringVar()
        self.auth_tx_var.set(os.getenv("AUTH_TX", ""))
        self.auth_tx_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "AUTH_TX", self.auth_tx_var.get())
        )
        ttk.Label(parent, text="Auth TX ID (override):").grid(row=6, column=1, sticky="e", padx=5, pady=5)
        ttk.Entry(parent, textvariable=self.auth_tx_var, width=50).grid(row=6, column=2)

        # Run button
        ttk.Button(parent, text="Decrypt", command=self._on_decrypt).grid(row=7, column=2, pady=10)

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
        path = filedialog.askopenfilename(filetypes=[("SPWN package","*.spwn"), ("All files","*")])
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

    def _browse_dec_wallet(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json"), ("All files","*")])
        if path:
            self.dec_wallet_var.set(path)

    def _browse_source(self):
        path = filedialog.askopenfilename(filetypes=[("SPWN package","*.spwn"), ("All files","*")])
        if path:
            self.source_var.set(path)

    def _browse_dec_keyfile(self):
        path = filedialog.askopenfilename(filetypes=[("Wrapped key","*.*")])
        if path:
            self.dec_keyfile_var.set(path)

    # Button callbacks
    def _on_authorize(self):
        self._log("Starting authorize...")
        threading.Thread(target=self._do_authorize, daemon=True).start()

    def _do_authorize(self):
        code = authorize(
            caller_wallet   = self.caller_wallet_var.get() or None,
            new_user_wallet = self.new_wallet_var.get(),
            contract_or_spwn= self.contract_var.get(),
            key_file        = self.keyfile_var.get() or None
        )
        self._log(f"Authorize completed with exit code {code}")

    def _on_decrypt(self):
        self._log("Tales from decrypt...")
        threading.Thread(target=self._do_decrypt, daemon=True).start()

    def _do_decrypt(self):
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        try:
            code = decrypt_asset(
                wallet_file = self.dec_wallet_var.get(),
                source      = self.source_var.get(),
                key_file    = self.dec_keyfile_var.get() or None,
                auth_tx     = self.auth_tx_var.get() or None,
                output_dir  = self.output_dir_var.get() or None
            )
        finally:
            sys.stdout = old_stdout

        # replay any printed lines into our log
        for line in buf.getvalue().splitlines():
            self._log(line)
        #self._log(f"Decrypt completed with exit code {code}")


if __name__ == "__main__":
    app = SpawnGUI()
    app.mainloop()

def main():
    app = SpawnGUI()
    app.mainloop()