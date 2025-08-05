#!/usr/bin/env python3
# extract_flat.py
# Name: Inkstract
# Author: Cuttlescript (https://github.com/cuttlescript)
# Version: 1.5
# Date: 2025-08-05
# Requires Python 3.10+
#
# Flattens and extracts (optionally filtered) files from all ZIPs in a folder,
# with recursive search, verbosity control, robust error handling,
# and true cross-platform filename sanitisation.

import argparse
import itertools
import shutil
import zipfile
import sys
from pathlib import Path
import logging
import re
import os
import signal

# Ensure correct Python version
if sys.version_info < (3, 10):
    print('Error: Python 3.10 or higher is required.')
    sys.exit(1)


def sanitise_filename(name: str) -> str:
    """Sanitise filenames to avoid OS/FS issues and constrain length."""
    # Remove control chars
    name = re.sub(r'[\x00-\x1f\x7f]', '_', name)
    # Replace forbidden chars
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Collapse whitespace
    name = re.sub(r'\s+', ' ', name).strip()
    # Determine max filename length in a cross-platform-safe way
    try:
        max_len = os.pathconf('.', 'PC_NAME_MAX')
    except (AttributeError, OSError):
        max_len = 255
    # Truncate to allowed length
    if len(name) > max_len:
        name = name[:max_len]
    # Fallback for empty names
    return name or 'file'


def unique_path(dest: Path, name: str) -> Path:
    """Generate a unique path in dest for a given filename (adds _1, _2 etc if needed)."""
    stem, suffix = Path(name).stem, Path(name).suffix
    for n in itertools.count():
        suffix_n = '' if n == 0 else f'_{n}'
        candidate = dest / f'{stem}{suffix_n}{suffix}'
        if not candidate.exists():
            return candidate


def extract(
    zip_dir: Path,
    out_dir: Path,
    keep_exts: set[str] | None,
    logger: logging.Logger,
    dry_run: bool,
    verbose: bool,
    quiet: bool,
    recursive: bool
) -> dict:
    """Extract files matching keep_exts from ZIPs in zip_dir to out_dir.
    Supports recursion, verbosity control, and detailed error handling."""
    stats = {'files': 0, 'errors': 0}

    if not zip_dir.exists() or not zip_dir.is_dir():
        print(f'Error: zip_dir "{zip_dir}" is not a valid directory.')
        sys.exit(1)

    # Build list of ZIP files (case-insensitive) by checking suffix lower()
    glob_func = zip_dir.rglob if recursive else zip_dir.glob
    all_files = glob_func('*')
    zip_files = sorted(
        f for f in all_files
        if f.is_file() and f.suffix.lower() == '.zip'
    )
    total = len(zip_files)

    if total == 0 and not quiet:
        print('No zip files found.')
        return stats

    for i, zfile in enumerate(zip_files, 1):
        if not quiet:
            print(f'Processing file {i}/{total}: {zfile}')
        try:
            with zipfile.ZipFile(zfile) as z:
                for member in z.infolist():
                    if member.is_dir():
                        continue
                    ext = Path(member.filename).suffix.lower()
                    if keep_exts and ext not in keep_exts:
                        continue
                    out_name = sanitise_filename(Path(member.filename).name)
                    out_path = unique_path(out_dir, out_name)
                    if dry_run:
                        if verbose and not quiet:
                            print(f'[DRY RUN] {member.filename} -> {out_path}')
                        stats['files'] += 1
                        continue
                    try:
                        with z.open(member) as src, open(out_path, 'wb') as dst:
                            shutil.copyfileobj(src, dst)
                        stats['files'] += 1
                        if verbose and not quiet:
                            print(f'Extracted {member.filename} -> {out_path}')
                    except (PermissionError, OSError) as e:
                        logger.error(f'Permission error writing {out_path}: {e}')
                        stats['errors'] += 1
                    except Exception as e:
                        logger.error(f'Failed to extract {member.filename} from {zfile.name}: {e}')
                        stats['errors'] += 1
        except zipfile.BadZipFile:
            logger.error(f'Bad zip file: {zfile}')
            stats['errors'] += 1
        except PermissionError as e:
            logger.error(f'Permission denied reading zip file {zfile}: {e}')
            stats['errors'] += 1
        except Exception as e:
            logger.error(f'Failed to process {zfile.name}: {e}')
            stats['errors'] += 1
    return stats


def main() -> None:
    # Graceful interrupt for SIGINT and SIGTERM
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda s, f: sys.exit(0))

    parser = argparse.ArgumentParser(description='Flatten-extract files from ZIPs')
    parser.add_argument('zip_dir', type=Path, help='Folder containing ZIP files')
    parser.add_argument('out_dir', type=Path, help='Destination folder')
    parser.add_argument('-e', '--exts', help='Comma-separated extensions (e.g. .png,.jpg)')
    parser.add_argument('--dry-run', action='store_true',
                        help="List files that would be extracted, but don't write anything.")
    parser.add_argument('-r', '--recursive', action='store_true', help='Search subdirectories for ZIP files.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show every file extracted.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress per-file and per-zip messages.')
    args = parser.parse_args()

    # Parse extensions
    exts = ({e.lower() if e.startswith('.') else f'.{e.lower()}'
             for e in args.exts.split(',') if e.strip()} if args.exts else None)

    # Prepare out_dir
    try:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Error: cannot create output directory "{args.out_dir}": {e}')
        sys.exit(1)
    if not args.out_dir.is_dir() or not os.access(args.out_dir, os.W_OK):
        print(f'Error: output directory "{args.out_dir}" is not writable.')
        sys.exit(1)

    # Setup logging
    log_path = args.out_dir / 'extract_flat.log'
    logging.basicConfig(filename=log_path,
                        level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    logger = logging.getLogger('extract_flat')

    if not args.quiet:
        print(f'Starting extraction: {args.zip_dir} -> {args.out_dir}')

    try:
        stats = extract(
            zip_dir=args.zip_dir,
            out_dir=args.out_dir,
            keep_exts=exts,
            logger=logger,
            dry_run=args.dry_run,
            verbose=args.verbose,
            quiet=args.quiet,
            recursive=args.recursive
        )
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Unexpected error: {e}')
        sys.exit(1)

    # Summary
    suffix = 'would be ' if args.dry_run else ''
    print(f"Done. Files {suffix}extracted: {stats['files']}, Errors: {stats['errors']}")
    if not args.quiet:
        print(f'Log written to: {log_path}')

if __name__ == '__main__':
    main()
