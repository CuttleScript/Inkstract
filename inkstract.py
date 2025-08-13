#!/usr/bin/env python3
# inkstract.py
# Name: Inkstract
# Author: Cuttlescript (https://github.com/cuttlescript)
# Version: 2.5
# Date: 2025-08-13
# Requires Python 3.10+
#
# Flattens and extracts (optionally filtered) files from all ZIPs in a folder,
# with recursive search, verbosity control, robust error handling,
# and true cross-platform filename sanitisation. Atomic writes, zip-bomb guards,
# cumulative limits, timeout, optional password support (ZipCrypto), AES pre-detect,
# and path-length checks.

import argparse
import itertools
import zipfile
import sys
from pathlib import Path
import logging
import re
import os
import signal
import unicodedata
from tempfile import NamedTemporaryFile
import time
from typing import Optional
import functools
import random

# Ensure correct Python version
if sys.version_info < (3, 10):
    print('Error: Python 3.10 or higher is required.')
    sys.exit(1)

WINDOWS_RESERVED = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
})

# Default buffer size (MiB), overridable via CLI
DEFAULT_BUF_MIB = 8


class GlobalLimitExceeded(Exception):
    """Raised when streaming extraction would exceed the global total-bytes cap."""
    pass


def _fs_name_max(path: Path) -> int:
    """Best-effort per-filesystem safe filename length (single path component)."""
    if os.name == 'nt':
        return 255
    try:
        return os.pathconf(str(path), 'PC_NAME_MAX')  # type: ignore[attr-defined]
    except Exception:
        return 255


def _fs_path_max(path: Path) -> int:
    """Best-effort full path length limit for the filesystem."""
    if os.name == 'nt':
        # Long paths require opt-in; conservative default.
        return 260 if not os.environ.get('LongPathsEnabled') else 32767
    try:
        return os.pathconf(str(path), 'PC_PATH_MAX')  # type: ignore[attr-defined]
    except Exception:
        return 4096


def sanitise_filename(name: str, target_dir: Path | None = None) -> str:
    """Sanitise filenames to avoid OS/FS issues and constrain length (Windows-safe)."""
    # Normalise unicode
    name = unicodedata.normalize("NFC", name)
    # Remove control chars
    name = re.sub(r'[\x00-\x1f\x7f]', '_', name)
    # Replace forbidden chars
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Collapse whitespace
    name = re.sub(r'\s+', ' ', name).strip()

    stem, suf = os.path.splitext(name)
    base = (stem or '').rstrip(' .')
    ext = (suf or '').rstrip(' .')
    if (base or '').upper() in WINDOWS_RESERVED:
        base = f'_{base}'
    name = ((base or 'file') + ext) or 'file'

    # Constrain length using target FS if provided
    max_len = _fs_name_max(target_dir if target_dir else Path('.'))
    if len(name) > max_len:
        stem2, suf2 = os.path.splitext(name)
        keep = max(1, max_len - len(suf2))
        name = stem2[:keep] + suf2
    return name or 'file'


def unique_path(dest: Path, name: str) -> Path:
    """Generate a unique path in dest for a given filename (adds _1, _2, ...; hashes if too many)."""
    p = Path(name)
    stem = p.stem
    suffix = p.suffix
    for n in itertools.count():
        candidate = dest / (f"{stem}{'' if n == 0 else f'_{n}'}{suffix}")
        if not candidate.exists():
            return candidate
        if n >= 100:
            # After many clashes, use a short random hash to avoid O(n) churn.
            h = f"{random.getrandbits(24):06x}"
            cand = dest / f"{stem}_{h}{suffix}"
            if not cand.exists():
                return cand


def _is_encrypted(member: zipfile.ZipInfo) -> bool:
    # Traditional PKZip encryption bit
    return bool(member.flag_bits & 0x1)


def _is_probably_aes(member: zipfile.ZipInfo) -> bool:
    """Best-effort detection of WinZip AES (extra field 0x9901)."""
    extra = getattr(member, "extra", b"") or b""
    i = 0
    # Parse TLV: [2B header id][2B data size][data...]
    while i + 4 <= len(extra):
        header_id = int.from_bytes(extra[i:i+2], "little")
        data_size = int.from_bytes(extra[i+2:i+4], "little")
        i += 4
        if i + data_size > len(extra):
            break
        if header_id == 0x9901:
            return True
        i += data_size
    return False


def _is_regular_file(member: zipfile.ZipInfo, logger: logging.Logger | None = None) -> bool:
    """Accept only regular files (or unknown mode). Reject symlinks and special files."""
    mode_type = (member.external_attr >> 16) & 0xF000
    # 0x8000: regular; 0xA000: symlink; 0x4000: dir. Accept unknown (0) and regular.
    if mode_type == 0 and logger:
        logger.debug(f'Entry mode unknown (treating as regular): {member.filename}')
    return mode_type in (0, 0x8000)


def _safe_extract_member(
    z: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    out_path: Path,
    max_uncompressed: int,
    max_ratio: float,
    pwd: Optional[bytes],
    remaining_global_bytes: Optional[int],
    buf_size: int,
) -> int:
    """Extract a single member with atomic write and safety guards.

    Returns the actual number of bytes written.
    """
    # Basic encryption checks (outer loop also handles with logging)
    if _is_encrypted(member):
        if _is_probably_aes(member):
            raise RuntimeError("AES-encrypted entry not supported by stdlib zipfile; use pyzipper")
        if not pwd:
            raise RuntimeError("Encrypted entry not supported (no password provided)")

    if member.file_size > max_uncompressed:
        # Header says it's too big — fast fail.
        raise RuntimeError(f"Entry too large: {member.file_size} bytes (limit {max_uncompressed})")

    if member.file_size and member.compress_size == 0:
        # Non-zero file with zero compressed size is suspect; skip
        raise RuntimeError("Suspicious: non-zero file with zero compressed size")

    if member.compress_size:
        # Avoid false positives on tiny compressed sizes
        if member.compress_size >= 32 and (member.file_size / max(member.compress_size, 1)) > max_ratio:
            raise RuntimeError(f"Suspicious compression ratio > {max_ratio}x")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write stream to a temp file
    with z.open(member, pwd=pwd) as src, NamedTemporaryFile(dir=out_path.parent, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        copied = 0
        buf = bytearray(buf_size)
        mv = memoryview(buf)
        try:
            while True:
                n = src.readinto(mv)
                if not n:
                    break
                tmp.write(mv[:n])
                copied += n
                if copied > max_uncompressed:
                    raise RuntimeError(
                        f"Entry exceeded per-file limit while extracting (> {max_uncompressed} bytes)"
                    )
                if remaining_global_bytes is not None and copied > remaining_global_bytes:
                    # Abort cleanly; caller will handle and stop processing further entries/zips.
                    raise GlobalLimitExceeded(
                        "Extraction would exceed the global max-total bytes limit"
                    )
            # Fully flush the temp file before closing (helps AV/indexers)
            tmp.flush()
            os.fsync(tmp.fileno())
        except Exception:
            # Ensure temp file doesn’t get orphaned
            try:
                tmp_path.unlink(missing_ok=True)
            finally:
                raise

    # Now the temp file is CLOSED — do an atomic-ish replace with a short retry on Windows locks
    def _replace_with_retry(src_path: Path, dst_path: Path) -> Path:
        last_err = None
        target = dst_path
        for attempt in range(10):
            try:
                src_path.replace(target)
                return target
            except FileExistsError:
                # Race: target appeared between write and replace; choose a unique name
                target = unique_path(target.parent, target.name)
            except OSError as e:
                # Handle transient locks (AV/indexer/thumbnailer). Back off briefly.
                last_err = e
                time.sleep(0.1 * (attempt + 1))
        # If we’re here, all retries failed
        raise last_err if last_err else OSError("Unknown replace error")

    try:
        final_path = _replace_with_retry(Path(tmp_path), out_path)
    except Exception:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        finally:
            raise

    return os.path.getsize(final_path)


def extract(
    zip_dir: Path,
    out_dir: Path,
    keep_exts: set[str] | None,
    exclude_exts: set[str] | None,
    name_regex: re.Pattern[str] | None,
    logger: logging.Logger,
    dry_run: bool,
    verbose: bool,
    quiet: bool,
    recursive: bool,
    overwrite: bool,
    max_uncompressed: int,
    max_ratio: float,
    max_total_bytes: Optional[int],
    max_files: Optional[int],
    timeout_seconds: Optional[int],
    password: Optional[str],
    buf_mib: int,
) -> dict:
    """Extract files matching filters from ZIPs in zip_dir to out_dir."""
    stats = {
        'files': 0,
        'errors': 0,
        'zips': 0,
        'skipped_encrypted': 0,
        'skipped_filtered': 0,
        'skipped_nonregular': 0,
        'aborted': False,
    }
    start = time.monotonic()
    total_bytes = 0
    pwd_bytes = password.encode() if password else None
    buf_size = max(1, buf_mib) * 1024 * 1024

    if not zip_dir.exists() or not zip_dir.is_dir():
        print(f'Error: zip_dir "{zip_dir}" is not a valid directory.')
        sys.exit(1)

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
        stats['zips'] += 1
        if not quiet:
            print(f'Processing file {i}/{total}: {zfile}')
        logger.info('Processing ZIP %d/%d: %s', i, total, zfile)
        matched_this_zip = 0
        aborted_this_zip = False

        # Global brakes check before opening another zip
        if timeout_seconds and (time.monotonic() - start) > timeout_seconds:
            logger.error('Aborting: timeout exceeded before processing next ZIP')
            stats['aborted'] = True
            break
        if max_files and stats['files'] >= max_files:
            logger.error('Aborting: max files limit reached before processing next ZIP')
            stats['aborted'] = True
            break
        if max_total_bytes and total_bytes >= max_total_bytes:
            logger.error('Aborting: max total bytes limit reached before processing next ZIP')
            stats['aborted'] = True
            break

        try:
            with zipfile.ZipFile(zfile) as z:
                for member in z.infolist():
                    if member.is_dir():
                        continue
                    if not _is_regular_file(member, logger):
                        logger.warning(f'Skipping non-regular entry: {member.filename}')
                        stats['skipped_nonregular'] += 1
                        continue

                    # Paranoia: even though we flatten to basename, log traversal-y names
                    if '..' in member.filename.replace('\\', '/'):
                        logger.debug(f"Entry name contains '..': {member.filename}")

                    # Global brakes within zip
                    if timeout_seconds and (time.monotonic() - start) > timeout_seconds:
                        logger.error('Aborting: timeout exceeded')
                        aborted_this_zip = True
                        stats['aborted'] = True
                        break
                    if max_files and stats['files'] >= max_files:
                        logger.error('Aborting: max files limit reached')
                        aborted_this_zip = True
                        stats['aborted'] = True
                        break
                    if max_total_bytes and total_bytes >= max_total_bytes:
                        logger.error('Aborting: max total bytes limit reached')
                        aborted_this_zip = True
                        stats['aborted'] = True
                        break

                    src_name = Path(member.filename).name
                    ext = Path(src_name).suffix.lower()

                    # Filtering decisions
                    filtered_out = False
                    if keep_exts and ext not in keep_exts:
                        filtered_out = True
                    if exclude_exts and ext in exclude_exts:
                        filtered_out = True
                    if name_regex and not name_regex.search(src_name):
                        filtered_out = True
                    if filtered_out:
                        stats['skipped_filtered'] += 1
                        continue

                    out_name = sanitise_filename(src_name, out_dir)
                    out_path = (out_dir / out_name) if overwrite else unique_path(out_dir, out_name)

                    # Path length guard (bytes-aware)
                    try:
                        full_path_bytes = os.fsencode(out_path)
                        if len(full_path_bytes) > _fs_path_max(out_path.parent):
                            raise OSError('Path too long for filesystem')
                    except Exception as e:
                        logger.error(f'Path too long or invalid: {out_path} ({e})')
                        stats['errors'] += 1
                        continue

                    # Encryption handling at outer layer for logging clarity
                    if _is_encrypted(member):
                        if _is_probably_aes(member):
                            logger.warning('Skipping AES-encrypted entry (unsupported by stdlib): %s', member.filename)
                            stats['skipped_encrypted'] += 1
                            continue
                        if not pwd_bytes:
                            logger.warning('Skipping encrypted entry (no password): %s', member.filename)
                            stats['skipped_encrypted'] += 1
                            continue

                    if dry_run:
                        matched_this_zip += 1
                        stats['files'] += 1
                        # Log per-file (dry run)
                        logger.info('[DRY RUN] %s -> %s', member.filename, out_path)
                        if verbose and not quiet:
                            print(f'[DRY RUN] {member.filename} -> {out_path}')
                        continue

                    try:
                        remaining_global = None
                        if max_total_bytes is not None:
                            remaining_global = max(0, max_total_bytes - total_bytes)

                        written = _safe_extract_member(
                            z=z,
                            member=member,
                            out_path=out_path,
                            max_uncompressed=max_uncompressed,
                            max_ratio=max_ratio,
                            pwd=pwd_bytes,
                            remaining_global_bytes=remaining_global,
                            buf_size=max(1, DEFAULT_BUF_MIB) * 1024 * 1024 if False else max(1, buf_mib) * 1024 * 1024,
                        )

                        matched_this_zip += 1
                        stats['files'] += 1
                        total_bytes += written
                        # Log per-file (real extraction)
                        logger.info('Extracted %s -> %s (%d bytes)', member.filename, out_path, written)
                        if verbose and not quiet:
                            print(f'Extracted {member.filename} -> {out_path}')
                    except GlobalLimitExceeded as e:
                        logger.error(f'{e}. Aborting further extraction.')
                        aborted_this_zip = True
                        stats['aborted'] = True
                        break
                    except (PermissionError, OSError) as e:
                        logger.error(f'Permission error writing {out_path}: {e}')
                        stats['errors'] += 1
                    except RuntimeError as e:
                        # Includes encrypted-with-unsupported-AES or bomby entries
                        msg = str(e).lower()
                        if 'aes' in msg or ('encrypted' in msg and pwd_bytes):
                            logger.warning(f'Encrypted entry not supported (likely AES): {member.filename}')
                            stats['skipped_encrypted'] += 1
                        else:
                            logger.error(f'Failed to extract {member.filename} from {zfile.name}: {e}')
                            stats['errors'] += 1
                    except Exception as e:
                        logger.error(f'Failed to extract {member.filename} from {zfile.name}: {e}')
                        stats['errors'] += 1
        except zipfile.BadZipFile:
            logger.error(f'Bad zip file: {zfile}')
            stats['errors'] += 1
        except zipfile.LargeZipFile as e:
            logger.error(f'ZIP64 issue for {zfile}: {e}')
            stats['errors'] += 1
        except PermissionError as e:
            logger.error(f'Permission denied reading zip file {zfile}: {e}')
            stats['errors'] += 1
        except Exception as e:
            logger.error(f'Failed to process {zfile.name}: {e}')
            stats['errors'] += 1

        if not quiet:
            extra = ''
            if aborted_this_zip:
                extra = ' (aborted due to limits/timeout)'
            print(f'  -> matched {matched_this_zip} file(s){extra}')
        logger.info('ZIP done: %s (matched %d)%s',
                    zfile, matched_this_zip,
                    ' [aborted early]' if aborted_this_zip else '')

        # Stop early if any global brakes hit
        if aborted_this_zip:
            break

    return stats


def main() -> None:
    # Graceful interrupt for SIGINT/SIGTERM where available
    def _exit_for_signal(sig_num: int):
        if hasattr(signal, 'SIGINT') and sig_num == signal.SIGINT:
            logging.shutdown()
            sys.exit(130)  # 128 + SIGINT
        if hasattr(signal, 'SIGTERM') and sig_num == signal.SIGTERM:
            logging.shutdown()
            sys.exit(143)  # 128 + SIGTERM
        logging.shutdown()
        sys.exit(1)

    for sig_name in ('SIGINT', 'SIGTERM'):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            signal.signal(sig, functools.partial(lambda sn, s, f: _exit_for_signal(sn), sig))

    parser = argparse.ArgumentParser(description='Flatten-extract files from ZIPs')
    parser.add_argument('zip_dir', type=Path, help='Folder containing ZIP files')
    parser.add_argument('out_dir', type=Path, help='Destination folder')
    parser.add_argument('-e', '--exts', help='Comma-separated extensions to KEEP (e.g. .png,.jpg)')
    parser.add_argument('--exclude-exts', help='Comma-separated extensions to EXCLUDE (e.g. .txt,.md)')
    parser.add_argument('--name-regex', help='Regex to match filenames to extract (applied to basename)')
    parser.add_argument('--dry-run', action='store_true',
                        help="List files that would be extracted, but don't write anything.")
    parser.add_argument('-r', '--recursive', action='store_true', help='Search subdirectories for ZIP files.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show every file extracted.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress per-file and per-zip messages.')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing files instead of adding _1, _2, ...')
    parser.add_argument('--fail-on-error', action='store_true', help='Exit with code 2 if any errors occurred.')
    parser.add_argument('--max-bytes', type=str, default='2G',
                        help='Max uncompressed size per entry (e.g. 500M, 2G). Default 2G.')
    parser.add_argument('--max-ratio', type=float, default=200.0,
                        help='Max expansion ratio (uncompressed/compressed). Default 200.')
    parser.add_argument('--max-total', type=str,
                        help='Max TOTAL uncompressed bytes to extract across all entries (e.g. 5G).')
    parser.add_argument('--max-files', type=int,
                        help='Max number of files to extract across all zips.')
    parser.add_argument('--timeout', type=int,
                        help='Abort after N seconds of wall time.')
    parser.add_argument('--password',
                        help='Password for encrypted entries (ZipCrypto only; AES may not be supported by stdlib). If omitted, encrypted entries are skipped.')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG','INFO','WARNING','ERROR','CRITICAL'],
                        help='File/console log level. Default INFO.')
    parser.add_argument('--no-console-log', action='store_true',
                        help='Disable logging to stderr (logs still go to file).')
    parser.add_argument('--buf-mib', type=int, default=DEFAULT_BUF_MIB,
                        help=f'I/O buffer size in MiB for extraction reads. Default {DEFAULT_BUF_MIB}.')

    args = parser.parse_args()

    def _parse_exts(s: str | None) -> set[str] | None:
        if not s:
            return None
        out: set[str] = set()
        for raw in s.split(','):
            e = raw.strip()
            if not e:
                continue
            e = e.lower()
            if not e.startswith('.'):
                e = '.' + e
            out.add(e)
        return out or None

    def _parse_size(s: str) -> int:
        m = re.fullmatch(r'\s*(\d+(?:\.\d+)?)\s*([kKmMgGtT]?(?:[iI]?[bB])?)?\s*', s)
        if not m:
            raise argparse.ArgumentTypeError(f'Invalid size: {s}')
        num = float(m.group(1))
        unit = (m.group(2) or '').lower()
        mult = 1
        if unit.startswith('k'):
            mult = 1024
        elif unit.startswith('m'):
            mult = 1024**2
        elif unit.startswith('g'):
            mult = 1024**3
        elif unit.startswith('t'):
            mult = 1024**4
        return int(num * mult)

    keep_exts = _parse_exts(args.exts)
    exclude_exts = _parse_exts(args.exclude_exts)
    # Case-insensitive by default
    name_regex = re.compile(args.name_regex, re.IGNORECASE) if args.name_regex else None
    max_uncompressed = _parse_size(args.max_bytes)
    max_total = _parse_size(args.max_total) if args.max_total else None

    # Prepare out_dir
    try:
        args.out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f'Error: cannot create output directory "{args.out_dir}": {e}')
        sys.exit(1)
    if not args.out_dir.is_dir() or not os.access(args.out_dir, os.W_OK):
        print(f'Error: output directory "{args.out_dir}" is not writable.')
        sys.exit(1)

    # Setup logging (file + optional console) — separate file for dry vs real
    log_path = args.out_dir / ('inkstract_dryrun.log' if args.dry_run else 'inkstract.log')
    logger = logging.getLogger('inkstract')
    logger.setLevel(getattr(logging, args.log_level.upper(), logging.INFO))
    logger.handlers.clear()
    # File handler
    fh = logging.FileHandler(log_path, encoding='utf-8')
    fh.setLevel(logger.level)
    fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(fh)
    # Console handler (optional)
    if not args.no_console_log:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logger.level)
        ch.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
        logger.addHandler(ch)

    # Always log a start line so the file isn't empty on success
    logger.info(
        'Starting %s: %s -> %s (recursive=%s, overwrite=%s, max_bytes=%s, max_total=%s, max_files=%s, timeout=%s)',
        'DRY RUN' if args.dry_run else 'EXTRACTION',
        args.zip_dir, args.out_dir, args.recursive, args.overwrite,
        args.max_bytes, args.max_total, args.max_files, args.timeout
    )

    if not args.quiet:
        print(f'Starting extraction: {args.zip_dir} -> {args.out_dir}')

    try:
        stats = extract(
            zip_dir=args.zip_dir,
            out_dir=args.out_dir,
            keep_exts=keep_exts,
            exclude_exts=exclude_exts,
            name_regex=name_regex,
            logger=logger,
            dry_run=args.dry_run,
            verbose=args.verbose,
            quiet=args.quiet,
            recursive=args.recursive,
            overwrite=args.overwrite,
            max_uncompressed=max_uncompressed,
            max_ratio=args.max_ratio,
            max_total_bytes=max_total,
            max_files=args.max_files,
            timeout_seconds=args.timeout,
            password=args.password,
            buf_mib=args.buf_mib,
        )
    except Exception as e:
        logger.error(f'Unexpected error: {e}')
        print(f'Unexpected error: {e}')
        logging.shutdown()
        sys.exit(1)

    # Summary
    suffix = 'would be ' if args.dry_run else ''
    print(f"Done. Files {suffix}extracted: {stats['files']}, Errors: {stats['errors']}, ZIPs processed: {stats['zips']}")
    # Mirror the summary into the log
    logger.info("Summary: files%s extracted=%d, errors=%d, zips=%d, skipped_encrypted=%d, skipped_filtered=%d, skipped_nonregular=%d, aborted=%s",
                ' (dry run)' if args.dry_run else '',
                stats['files'], stats['errors'], stats['zips'],
                stats.get('skipped_encrypted', 0), stats.get('skipped_filtered', 0),
                stats.get('skipped_nonregular', 0), stats.get('aborted', False))
    if stats.get('skipped_encrypted'):
        print(f"Encrypted entries skipped (no/unsupported password): {stats['skipped_encrypted']}")
    if stats.get('skipped_filtered'):
        print(f"Files skipped by filters: {stats['skipped_filtered']}")
    if stats.get('skipped_nonregular'):
        print(f"Non-regular entries skipped: {stats['skipped_nonregular']}")
    if stats.get('aborted'):
        print("Aborted early due to limits or timeout.")
    if not args.quiet:
        print(f'Log written to: {log_path}')

    # Exit codes:
    # 0 = success, 2 = errors encountered (when --fail-on-error), 3 = aborted due to limits/timeout
    exit_code = 0
    if stats.get('aborted'):
        exit_code = 3
    if stats['errors'] > 0 and getattr(args, 'fail_on_error', False):
        exit_code = 2

    logging.shutdown()
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
