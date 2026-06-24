#!/usr/bin/env python3
"""
export_backup.py - CFMS maintenance script

Creates an encrypted CFMS backup containing persistent database records and
their physical files.

Usage:
    python maintenance_scripts/export_backup.py backup.confbak
    python maintenance_scripts/export_backup.py backup.confbak --key-out backup.key

This script must be run from the `src/` directory so that `config.toml`,
storage paths, and the configured database are resolved correctly.
"""

import argparse
import os
import sys

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export an encrypted CFMS backup from the command line."
    )
    parser.add_argument("output", help="Path of the backup file to create")
    parser.add_argument(
        "--key-out",
        metavar="PATH",
        help="Optional file path where the generated decryption key will be written",
    )
    args = parser.parse_args()

    if not os.path.exists("config.toml"):
        print(
            "Error: 'config.toml' not found in the current directory.\n"
            "Please run this script from the 'src/' directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    from include.backup import BackupError, export_backup
    from include.providers.bootstrap import initialize_providers

    try:
        initialize_providers()
        key = export_backup(args.output, key_output_path=args.key_out)
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Backup written to: {args.output}")
    if args.key_out:
        print(f"Decryption key written to: {args.key_out}")
    else:
        print(f"Decryption key: {key}")
    print("Store this key safely - it is required to import the backup.")


if __name__ == "__main__":
    main()
