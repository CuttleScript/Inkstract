# Inkstract

**Flatten and extract ZIP files with inky precision.**

Inkstract is a small Python tool that goes through all the ZIP archives in a folder and pulls every file (or just the ones you want) into a single output folder. It makes sure filenames are safe, handles duplicates, and logs any errors.

---

## 📋 Features

- **Flat output**  
  All files end up in one folder with no internal folder structure.

- **Filter by type or name**  
  Only extract certain extensions, exclude unwanted ones, or match by regex.

- **Safe filenames**  
  Removes weird characters and limits length so nothing breaks.

- **Unique names or overwrite**  
  Auto-renames duplicates (`file.txt`, `file_1.txt`, etc) or overwrite existing files.

- **Dry run mode**  
  See what would be extracted without writing anything — separate log file for dry runs.

- **Recursive search**  
  Look inside subfolders for ZIPs.

- **Verbose or quiet**  
  Show every file as it’s extracted, or stay silent except for summary.

- **Error logging**  
  All permission issues, bad ZIPs, etc. go into `extract_flat.log` (or `extract_flat_dryrun.log` for dry runs).

- **Extraction limits**  
  Optional caps for per-file size, total size, file count, compression ratio, or run time.

---

## 🚀 Requirements

- Python **3.10** or newer  
- No extra libraries — only uses Python’s standard library.

---

## 🔧 Installation

1. Clone the repo (or download the code):  
   ```bash
   git clone https://github.com/your-username/Inkstract.git
   cd Inkstract
   ```

2. Check Python version:  
   ```bash
   python3 --version
   ```

---

## 📖 Usage

```bash
./inkstract.py [OPTIONS] <zip_folder> <output_folder>
```

### Options

| Option                | What it does |
|-----------------------|--------------|
| `-e, --exts`          | Comma-separated extensions to **keep** (e.g. `.png,.pdf`). |
| `--exclude-exts`      | Comma-separated extensions to **exclude** (e.g. `.txt,.md`). |
| `--name-regex`        | Case-insensitive regex to match filenames (applied to the basename). |
| `--dry-run`           | Don’t write any files — just log/print what would happen. Logs go to `extract_flat_dryrun.log`. |
| `-r, --recursive`     | Search subfolders for ZIP files. |
| `-v, --verbose`       | Print each file as it’s extracted (or would be in dry run). |
| `-q, --quiet`         | Suppress per-file messages (only summary at end). |
| `--overwrite`         | Overwrite existing files instead of adding `_1`, `_2`, etc. |
| `--fail-on-error`     | Exit with code 2 if any errors occur (default exit code is 0 unless aborted). |
| `--max-bytes`         | Max uncompressed size per file (e.g. `500M`, `2G`). Default `2G`. |
| `--max-ratio`         | Max compression expansion ratio allowed (uncompressed/compressed). Default `200.0`. |
| `--max-total`         | Max total uncompressed bytes extracted across all files (e.g. `5G`). |
| `--max-files`         | Max number of files to extract across all ZIPs. |
| `--timeout`           | Abort after N seconds wall time. |
| `--password`          | Password for ZipCrypto-encrypted entries. AES entries are auto-detected and skipped. |
| `--log-level`         | Set log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Default `INFO`. |
| `--no-console-log`    | Don’t log to stderr (logs still written to file). |
| `--buf-mib`           | I/O buffer size in MiB for extraction reads. Default `8`. |

---

## 💡 Examples

1. **Extract everything** from `zips/` into `out/`:
   ```bash
   ./inkstract.py zips/ out/
   ```

2. **Only pull images** (`.jpg` & `.png`):
   ```bash
   ./inkstract.py -e .jpg,.png zips/ out/
   ```

3. **Exclude certain file types** (e.g. skip `.txt` and `.md` files):
   ```bash
   ./inkstract.py --exclude-exts .txt,.md zips/ out/
   ```

4. **Use regex to match names** (case-insensitive):
   ```bash
   ./inkstract.py --name-regex "report_\d{4}" zips/ out/
   ```

5. **Dry run** with verbose output:
   ```bash
   ./inkstract.py --dry-run -v zips/ out/
   ```
   → Writes `extract_flat_dryrun.log` in `out/`.

6. **Recursive search + overwrite existing files**:
   ```bash
   ./inkstract.py -r --overwrite zips/ out/
   ```

7. **Set size limits**: max 50 MB per file, max 1 GB total, stop after 500 files:
   ```bash
   ./inkstract.py --max-bytes 50M --max-total 1G --max-files 500 zips/ out/
   ```

8. **Password-protected ZipCrypto files**:
   ```bash
   ./inkstract.py --password mysecret zips/ out/
   ```

9. **Quiet mode + custom log level**:
   ```bash
   ./inkstract.py -q --log-level DEBUG zips/ out/
   ```

---

## 📝 Logging Behaviour

- **Separate log files**:  
  • Dry run mode writes logs to `extract_flat_dryrun.log`.  
  • Real extraction writes logs to `extract_flat.log`.

- **Per-file logging**:  
  Every file that is (or would be) extracted is logged with full source and destination paths. This happens even in `--quiet` mode.

- **Summary logging**:  
  At the end of every run, a summary line is written to the log with totals for files, errors, skipped entries, and whether the process was aborted.

- **Log level control**:  
  Use `--log-level` to include debug details or suppress non-critical info. Set `--no-console-log` to write only to the file without printing to the console.

---

## 🛠️ Troubleshooting

- **“Error: Python 3.10 or higher is required.”**  
  Use a newer Python version.

- **Permission errors** in the log?  
  Check write access to the output folder.

- **No files extracted?**  
  • Verify ZIP folder path.  
  • Check filters (`--exts`, `--exclude-exts`, `--name-regex`).  

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

Happy inkstracting! 🦑✨
