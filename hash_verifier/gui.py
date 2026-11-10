"""Tkinter graphical interface for the hash verifier."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from hash_verifier.core import (
    format_verify_report,
    load_manifest,
    save_manifest,
    scan_directories,
    verify_against_manifest,
)


class HashVerifierApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Hash Verifier — SHA-256 Integrity Scanner")
        self.minsize(720, 520)
        self.geometry("900x620")

        self._directories: list[str] = []
        self._busy = False

        self._build_ui()

    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 4}

        header = ttk.Label(
            self,
            text="Scan directories, save a SHA-256 baseline, then verify later to detect changes.",
            wraplength=860,
        )
        header.pack(fill="x", **pad)

        dir_frame = ttk.LabelFrame(self, text="Directories to monitor")
        dir_frame.pack(fill="both", expand=False, **pad)

        list_row = ttk.Frame(dir_frame)
        list_row.pack(fill="both", expand=True, padx=8, pady=8)

        self.dir_listbox = tk.Listbox(list_row, height=6, selectmode=tk.EXTENDED)
        scroll = ttk.Scrollbar(list_row, orient="vertical", command=self.dir_listbox.yview)
        self.dir_listbox.configure(yscrollcommand=scroll.set)
        self.dir_listbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        btn_row = ttk.Frame(dir_frame)
        btn_row.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(btn_row, text="Add folder…", command=self._add_directory).pack(
            side="left", padx=(0, 4)
        )
        ttk.Button(btn_row, text="Remove selected", command=self._remove_selected).pack(
            side="left", padx=4
        )
        ttk.Button(btn_row, text="Clear all", command=self._clear_directories).pack(
            side="left", padx=4
        )

        manifest_frame = ttk.LabelFrame(self, text="Manifest file")
        manifest_frame.pack(fill="x", **pad)

        mf_inner = ttk.Frame(manifest_frame)
        mf_inner.pack(fill="x", padx=8, pady=8)

        self.manifest_var = tk.StringVar()
        ttk.Entry(mf_inner, textvariable=self.manifest_var).pack(
            side="left", fill="x", expand=True, padx=(0, 4)
        )
        ttk.Button(mf_inner, text="Browse…", command=self._browse_manifest).pack(
            side="left"
        )

        sec_frame = ttk.LabelFrame(self, text="Security (optional)")
        sec_frame.pack(fill="x", **pad)

        sec_inner = ttk.Frame(sec_frame)
        sec_inner.pack(fill="x", padx=8, pady=8)

        ttk.Label(sec_inner, text="Passphrase:").pack(side="left")
        self.passphrase_var = tk.StringVar()
        self.passphrase_entry = ttk.Entry(
            sec_inner, textvariable=self.passphrase_var, show="•", width=40
        )
        self.passphrase_entry.pack(side="left", padx=8)
        self.show_pass_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            sec_inner,
            text="Show passphrase",
            variable=self.show_pass_var,
            command=self._toggle_passphrase_visibility,
        ).pack(side="left")

        action_row = ttk.Frame(self)
        action_row.pack(fill="x", **pad)

        self.baseline_btn = ttk.Button(
            action_row,
            text="Create baseline",
            command=self._run_baseline,
        )
        self.baseline_btn.pack(side="left", padx=(0, 8))

        self.verify_btn = ttk.Button(
            action_row,
            text="Verify integrity",
            command=self._run_verify,
        )
        self.verify_btn.pack(side="left")

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=8, pady=4)

        log_frame = ttk.LabelFrame(self, text="Activity log")
        log_frame.pack(fill="both", expand=True, **pad)

        self.log = scrolledtext.ScrolledText(
            log_frame, height=14, state="disabled", wrap="word"
        )
        self.log.pack(fill="both", expand=True, padx=8, pady=8)

        status = ttk.Label(
            self,
            text="Uses SHA-256 (hashlib). Encrypted manifests need: pip install cryptography",
        )
        status.pack(fill="x", padx=8, pady=(0, 8))

    def _toggle_passphrase_visibility(self) -> None:
        self.passphrase_entry.configure(
            show="" if self.show_pass_var.get() else "•"
        )

    def _log_line(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self.baseline_btn.configure(state=state)
        self.verify_btn.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _add_directory(self) -> None:
        path = filedialog.askdirectory(title="Select directory to monitor")
        if path and path not in self._directories:
            self._directories.append(path)
            self.dir_listbox.insert("end", path)

    def _remove_selected(self) -> None:
        indices = list(self.dir_listbox.curselection())
        for index in reversed(indices):
            self.dir_listbox.delete(index)
            del self._directories[index]

    def _clear_directories(self) -> None:
        self.dir_listbox.delete(0, "end")
        self._directories.clear()

    def _browse_manifest(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Manifest file",
            defaultextension=".json",
            filetypes=[
                ("Manifest JSON", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.manifest_var.set(path)

    def _validate_inputs(self, need_dirs: bool = True) -> Path | None:
        if need_dirs and not self._directories:
            messagebox.showwarning(
                "No directories",
                "Add at least one directory before continuing.",
            )
            return None
        manifest = self.manifest_var.get().strip()
        if not manifest:
            messagebox.showwarning(
                "No manifest",
                "Choose a path for the manifest file.",
            )
            return None
        return Path(manifest)

    def _run_baseline(self) -> None:
        if self._busy:
            return
        manifest_path = self._validate_inputs()
        if not manifest_path:
            return

        passphrase = self.passphrase_var.get() or None

        def worker() -> None:
            try:
                self._log_line("Starting baseline scan…")

                def progress(rel: str, current: int, total: int) -> None:
                    self.after(
                        0,
                        lambda: self._log_line(f"  [{current}/{total}] {rel}"),
                    )

                scan = scan_directories(
                    self._directories,
                    manifest_path=manifest_path,
                    progress=progress,
                )
                save_manifest(
                    manifest_path,
                    self._directories,
                    scan.records,
                    passphrase=passphrase,
                )
                msg = (
                    f"Baseline saved to {manifest_path}\n"
                    f"Files hashed: {len(scan.records)}"
                )
                if passphrase:
                    msg += "\nManifest is encrypted and HMAC-signed."
                self.after(0, lambda: self._on_baseline_done(scan, msg))
            except Exception as exc:
                self.after(0, lambda: self._on_error("Baseline failed", str(exc)))

        self._set_busy(True)
        threading.Thread(target=worker, daemon=True).start()

    def _on_baseline_done(self, scan, msg: str) -> None:
        self._set_busy(False)
        self._log_line(msg)
        if scan.errors:
            for err in scan.errors:
                self._log_line(f"Warning: {err}")
        messagebox.showinfo("Baseline complete", msg)

    def _run_verify(self) -> None:
        if self._busy:
            return
        manifest_path = self._validate_inputs(need_dirs=False)
        if not manifest_path:
            return
        if not manifest_path.is_file():
            messagebox.showerror(
                "Manifest missing",
                f"No manifest found at:\n{manifest_path}",
            )
            return

        dirs = self._directories
        passphrase = self.passphrase_var.get() or None

        def worker() -> None:
            try:
                manifest = load_manifest(manifest_path, passphrase=passphrase)
                scan_dirs = dirs or manifest.get("directories", [])
                if not scan_dirs:
                    raise ValueError("No directories to scan.")

                self._log_line("Verifying integrity…")

                def progress(rel: str, current: int, total: int) -> None:
                    self.after(
                        0,
                        lambda: self._log_line(f"  [{current}/{total}] {rel}"),
                    )

                result = verify_against_manifest(
                    scan_dirs,
                    manifest,
                    manifest_path=manifest_path,
                    progress=progress,
                )
                report = format_verify_report(result)
                self.after(0, lambda: self._on_verify_done(result.ok, report))
            except Exception as exc:
                self.after(0, lambda: self._on_error("Verification failed", str(exc)))

        self._set_busy(True)
        threading.Thread(target=worker, daemon=True).start()

    def _on_verify_done(self, ok: bool, report: str) -> None:
        self._set_busy(False)
        self._log_line(report)
        if ok:
            messagebox.showinfo("Integrity OK", report)
        else:
            messagebox.showwarning("Tampering detected", report)

    def _on_error(self, title: str, detail: str) -> None:
        self._set_busy(False)
        self._log_line(f"ERROR: {detail}")
        messagebox.showerror(title, detail)


def run_gui() -> None:
    app = HashVerifierApp()
    app.mainloop()


if __name__ == "__main__":
    run_gui()
