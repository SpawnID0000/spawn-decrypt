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
from .wallet_gen import save_wallet_jwk


class GuiStdout:
    """File-like stdout that sends each line to self._log immediately."""
    def __init__(self, log_func):
        self.log = log_func
        self._buf = ""
    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
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
    def __init__(self):
        super().__init__()
        self.title("Spawn Decrypt GUI")
        self.geometry("800x500")
        self.minsize(800, 500)

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

        # Authorize tab
        self.auth_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.auth_frame, text="Authorize")
        self._build_authorize_tab(self.auth_frame)

        # Decrypt tab
        self.dec_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dec_frame, text="Decrypt")
        self._build_decrypt_tab(self.dec_frame)

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

        # Source (.spwn or TX ID)
        self.contract_var = tk.StringVar()
        self.contract_var.set(os.getenv("CONTRACT_OR_SPWN", ""))
        self.contract_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "CONTRACT_OR_SPWN", self.contract_var.get())
        )
        ttk.Label(parent, text="Source (.spwn or TX ID):").grid(row=1, column=1, sticky="e", padx=5, pady=5)
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

        # Source (.spwn or TX ID)
        self.source_var = tk.StringVar()
        self.source_var.set(os.getenv("SOURCE", ""))
        self.source_var.trace_add(
            "write",
            lambda *a: set_key(str(self.env_path), "SOURCE", self.source_var.get())
        )
        ttk.Label(parent, text="Source (.spwn or TX ID):").grid(row=2, column=1, sticky="e", padx=5, pady=5)
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
        self._log("Starting authorization...")
        threading.Thread(target=self._do_authorize, daemon=True).start()

    def _do_authorize(self):
        old_stdout = sys.stdout
        sys.stdout = GuiStdout(self._log)
        try:
            code = authorize(
                caller_wallet   = self.caller_wallet_var.get() or None,
                new_user_wallet = self.new_wallet_var.get(),
                contract_or_spwn= self.contract_var.get(),
                key_file        = self.keyfile_var.get() or None
            )
        finally:
            sys.stdout = old_stdout

    def _on_decrypt(self):
        self._log("Tales from decrypt...")
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

if __name__ == "__main__":
    app = SpawnGUI()
    app.mainloop()

def main():
    app = SpawnGUI()
    app.mainloop()