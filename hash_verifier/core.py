"""Core scanning, hashing, manifest I/O, and verification logic."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

MANIFEST_VERSION = 1
CHUNK_SIZE = 65536
DEFAULT_SKIP_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
    ".DS_Store",
    "Thumbs.db",
}
DEFAULT_SKIP_SUFFIXES = {".pyc", ".pyo", ".manifest", ".manifest.enc"}


@dataclass
class FileRecord:
    relative_path: str
    sha256: str
    size: int
    modified_utc: str

    def to_dict(self) -> dict:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size": self.size,
            "modified_utc": self.modified_utc,
        }

    @classmethod
    def from_dict(cls, data: dict) -> FileRecord:
        return cls(
            relative_path=data["relative_path"],
            sha256=data["sha256"],
            size=data["size"],
            modified_utc=data["modified_utc"],
        )


@dataclass
class ScanResult:
    records: list[FileRecord] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class VerifyResult:
    ok: bool
    missing: list[str] = field(default_factory=list)
    extra: list[str] = field(default_factory=list)
    tampered: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return bool(self.missing or self.extra or self.tampered or self.errors)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _should_skip(
    path: Path,
    root: Path,
    skip_names: set[str],
    skip_suffixes: set[str],
    manifest_path: Path | None,
) -> bool:
    if manifest_path and path.resolve() == manifest_path.resolve():
        return True
    name = path.name
    if name in skip_names:
        return True
    if path.suffix.lower() in skip_suffixes:
        return True
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    parts = rel.parts
    return any(part in skip_names for part in parts)


def scan_directories(
    directories: Iterable[str | Path],
    *,
    skip_names: set[str] | None = None,
    skip_suffixes: set[str] | None = None,
    manifest_path: Path | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> ScanResult:
    """Walk directories and compute SHA-256 for every regular file."""
    names = skip_names or set(DEFAULT_SKIP_NAMES)
    suffixes = skip_suffixes or set(DEFAULT_SKIP_SUFFIXES)
    roots = [Path(d).resolve() for d in directories]
    result = ScanResult()

    files_to_hash: list[tuple[Path, Path]] = []
    for root in roots:
        if not root.is_dir():
            result.errors.append(f"Not a directory: {root}")
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in names]
            current = Path(dirpath)
            for filename in filenames:
                full = current / filename
                if not full.is_file():
                    continue
                if _should_skip(full, root, names, suffixes, manifest_path):
                    result.skipped.append(str(full))
                    continue
                files_to_hash.append((root, full))

    total = len(files_to_hash)
    for index, (root, full) in enumerate(files_to_hash, start=1):
        rel = str(full.relative_to(root)).replace("\\", "/")
        if progress:
            progress(rel, index, total)
        try:
            stat = full.stat()
            root_key = str(root).replace("\\", "/")
            result.records.append(
                FileRecord(
                    relative_path=f"{root_key}/{rel}",
                    sha256=sha256_file(full),
                    size=stat.st_size,
                    modified_utc=datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                )
            )
        except OSError as exc:
            result.errors.append(f"{full}: {exc}")

    result.records.sort(key=lambda r: r.relative_path)
    return result


def build_manifest_payload(
    directories: list[str],
    records: list[FileRecord],
) -> dict:
    return {
        "version": MANIFEST_VERSION,
        "algorithm": "sha256",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "directories": [str(Path(d).resolve()) for d in directories],
        "file_count": len(records),
        "files": [r.to_dict() for r in records],
    }


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )


def _sign_payload(payload_bytes: bytes, passphrase: str, salt: bytes) -> str:
    key = _derive_key(passphrase, salt)
    return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()


def save_manifest(
    manifest_path: Path,
    directories: list[str],
    records: list[FileRecord],
    *,
    passphrase: str | None = None,
) -> None:
    """Save manifest as JSON; encrypt and HMAC-sign when passphrase is set."""
    payload = build_manifest_payload(directories, records)
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    manifest_path = manifest_path.resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    if passphrase:
        salt = os.urandom(16)
        signature = _sign_payload(body, passphrase, salt)
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise ImportError(
                "Passphrase protection requires the 'cryptography' package. "
                "Install with: pip install cryptography"
            ) from exc
        fernet_key = base64.urlsafe_b64encode(_derive_key(passphrase, salt))
        encrypted = Fernet(fernet_key).encrypt(body)
        envelope = {
            "encrypted": True,
            "salt": base64.b64encode(salt).decode("ascii"),
            "signature": signature,
            "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        }
        manifest_path.write_text(
            json.dumps(envelope, indent=2), encoding="utf-8"
        )
    else:
        manifest_path.write_bytes(body)


def load_manifest(
    manifest_path: Path,
    *,
    passphrase: str | None = None,
) -> dict:
    """Load and optionally decrypt or verify manifest."""
    raw = manifest_path.read_text(encoding="utf-8")
    data = json.loads(raw)

    if data.get("encrypted"):
        if not passphrase:
            raise ValueError(
                "This manifest is encrypted. Provide the passphrase used when "
                "creating the baseline."
            )
        salt = base64.b64decode(data["salt"])
        ciphertext = base64.b64decode(data["ciphertext"])
        try:
            from cryptography.fernet import Fernet
        except ImportError as exc:
            raise ImportError(
                "Passphrase protection requires the 'cryptography' package. "
                "Install with: pip install cryptography"
            ) from exc
        fernet_key = base64.urlsafe_b64encode(_derive_key(passphrase, salt))
        body = Fernet(fernet_key).decrypt(ciphertext)
        expected_sig = data["signature"]
        actual_sig = _sign_payload(body, passphrase, salt)
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError(
                "Manifest signature invalid. Wrong passphrase or manifest "
                "was tampered with."
            )
        return json.loads(body.decode("utf-8"))

    if data.get("version") == MANIFEST_VERSION and "files" in data:
        return data

    raise ValueError("Unrecognized manifest format.")


def verify_against_manifest(
    directories: list[str | Path],
    manifest: dict,
    *,
    manifest_path: Path | None = None,
    progress: Callable[[str, int, int], None] | None = None,
) -> VerifyResult:
    """Compare current directory hashes to a stored manifest."""
    outcome = VerifyResult(ok=True)
    scan = scan_directories(
        directories,
        manifest_path=manifest_path,
        progress=progress,
    )
    outcome.errors.extend(scan.errors)

    stored = {
        r["relative_path"]: FileRecord.from_dict(r) for r in manifest["files"]
    }
    current = {r.relative_path: r for r in scan.records}

    for path, record in stored.items():
        if path not in current:
            outcome.missing.append(path)
            continue
        live = current[path]
        if live.sha256 != record.sha256:
            outcome.tampered.append(path)

    for path in current:
        if path not in stored:
            outcome.extra.append(path)

    outcome.ok = not outcome.has_issues
    return outcome


def format_verify_report(result: VerifyResult) -> str:
    lines: list[str] = []
    if result.ok:
        lines.append("INTEGRITY OK - All files match the stored baseline.")
        return "\n".join(lines)

    lines.append("INTEGRITY FAILURE - Possible tampering or changes detected.")
    if result.tampered:
        lines.append("")
        lines.append("Modified (hash mismatch):")
        for path in sorted(result.tampered):
            lines.append(f"  • {path}")
    if result.missing:
        lines.append("")
        lines.append("Missing (in baseline, not found now):")
        for path in sorted(result.missing):
            lines.append(f"  • {path}")
    if result.extra:
        lines.append("")
        lines.append("New files (not in baseline):")
        for path in sorted(result.extra):
            lines.append(f"  • {path}")
    if result.errors:
        lines.append("")
        lines.append("Errors during scan:")
        for err in result.errors:
            lines.append(f"  • {err}")
    return "\n".join(lines)
