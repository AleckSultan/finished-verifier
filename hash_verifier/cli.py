"""Command-line interface for the hash verifier."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from hash_verifier.core import (
    format_verify_report,
    load_manifest,
    save_manifest,
    scan_directories,
    verify_against_manifest,
)


def _progress(rel: str, current: int, total: int) -> None:
    print(f"[{current}/{total}] {rel}", file=sys.stderr)


def cmd_baseline(args: argparse.Namespace) -> int:
    passphrase = args.passphrase
    if args.prompt_passphrase and not passphrase:
        passphrase = getpass.getpass("Passphrase (optional, Enter to skip): ")
        if not passphrase:
            passphrase = None

    manifest_path = Path(args.manifest).resolve()
    dirs = [str(Path(d).resolve()) for d in args.directories]

    print("Scanning directories...", file=sys.stderr)
    scan = scan_directories(
        dirs,
        manifest_path=manifest_path,
        progress=_progress if args.verbose else None,
    )
    if scan.errors:
        for err in scan.errors:
            print(f"Warning: {err}", file=sys.stderr)

    save_manifest(manifest_path, dirs, scan.records, passphrase=passphrase)
    print(
        f"Baseline saved: {manifest_path} ({len(scan.records)} files hashed)"
    )
    if passphrase:
        print("Manifest is encrypted and HMAC-signed.")
    else:
        print(
            "Manifest is plain JSON. Use --passphrase for encrypted storage."
        )
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    passphrase = args.passphrase
    if args.prompt_passphrase and not passphrase:
        passphrase = getpass.getpass("Passphrase (if manifest is encrypted): ")
        if not passphrase:
            passphrase = None

    manifest_path = Path(args.manifest).resolve()
    try:
        manifest = load_manifest(manifest_path, passphrase=passphrase)
    except (ValueError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    dirs = args.directories or manifest.get("directories", [])
    if not dirs:
        print("Error: No directories to scan.", file=sys.stderr)
        return 2

    print("Verifying integrity...", file=sys.stderr)
    result = verify_against_manifest(
        dirs,
        manifest,
        manifest_path=manifest_path,
        progress=_progress if args.verbose else None,
    )
    print(format_verify_report(result))
    return 0 if result.ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hash-verifier",
        description="SHA-256 directory integrity verifier",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show per-file progress"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    baseline = sub.add_parser(
        "baseline", help="Scan directories and save a hash manifest"
    )
    baseline.add_argument(
        "directories", nargs="+", help="One or more directories to scan"
    )
    baseline.add_argument(
        "-m",
        "--manifest",
        required=True,
        help="Path to write the manifest file",
    )
    baseline.add_argument(
        "-p", "--passphrase", help="Encrypt and sign the manifest"
    )
    baseline.add_argument(
        "--prompt-passphrase",
        action="store_true",
        help="Prompt for passphrase interactively",
    )
    baseline.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-file progress",
    )
    baseline.set_defaults(func=cmd_baseline)

    verify = sub.add_parser(
        "verify", help="Re-scan and compare against a saved manifest"
    )
    verify.add_argument(
        "directories",
        nargs="*",
        help="Directories to scan (defaults to paths stored in manifest)",
    )
    verify.add_argument(
        "-m", "--manifest", required=True, help="Path to the manifest file"
    )
    verify.add_argument(
        "-p", "--passphrase", help="Decrypt an encrypted manifest"
    )
    verify.add_argument(
        "--prompt-passphrase",
        action="store_true",
        help="Prompt for passphrase interactively",
    )
    verify.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show per-file progress",
    )
    verify.set_defaults(func=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
