#!/usr/bin/env python3
"""
import_backup.py - CFMS maintenance script

Imports an encrypted CFMS backup into an empty database and restores the
corresponding physical files.

Usage:
    python maintenance_scripts/import_backup.py --info backup.confbak
    python maintenance_scripts/import_backup.py backup.confbak --key <base64url-key>
    python maintenance_scripts/import_backup.py backup.confbak --key-file backup.key

This script must be run from the `src/` directory for a full import.
"""

import argparse
import os
import sys

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)


def _read_key_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect or import an encrypted CFMS backup."
    )
    parser.add_argument("backup", help="Path of the backup file")
    parser.add_argument(
        "--info",
        action="store_true",
        help="Only read and display the unencrypted backup header",
    )
    key_group = parser.add_mutually_exclusive_group()
    key_group.add_argument("--key", help="Base64url decryption key")
    key_group.add_argument(
        "--key-file",
        metavar="PATH",
        help="File containing the base64url decryption key",
    )
    args = parser.parse_args()

    from include.backup import BackupError, import_backup, read_backup_header

    if args.info:
        try:
            header = read_backup_header(args.backup)
        except BackupError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        print("CFMS backup: yes")
        print(f"Format version: {header.format_version}")
        print(f"Created at: {header.created_at}")
        print(f"Core version: {header.core_version}")
        print(f"Compression: {header.compression}")
        print(f"Encryption: {header.encryption}")
        return

    if not os.path.exists("config.toml"):
        print(
            "Error: 'config.toml' not found in the current directory.\n"
            "Please run this script from the 'src/' directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.key and not args.key_file:
        print("Error: --key or --key-file is required for import.", file=sys.stderr)
        sys.exit(1)

    from include.providers.bootstrap import initialize_providers

    try:
        key = args.key if args.key else _read_key_file(args.key_file)
        initialize_providers()
        result = import_backup(args.backup, key)
    except (BackupError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Imported backup created at: {result['created_at']}")
    print(f"Source core version: {result['core_version']}")
    print(f"Restored tables: {len(result['tables'])}")
    print(f"Restored files: {len(result['files'])}")


if __name__ == "__main__":
    main()
