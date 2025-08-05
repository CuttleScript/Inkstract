# Inkstract

**Flatten and extract ZIP files with inky precision.**

Inkstract is a small Python tool that goes through all the ZIP archives in a folder and pulls every file (or just the ones you want) into a single output folder. It makes sure filenames are safe, handles duplicates, and logs any errors.

---

## 📋 Features

- **Flat output**  
  All files end up in one folder with no internal folder structure.

- **Filter by file type**  
  Only extract certain extensions (e.g. `.jpg`, `.txt`) if you like.

- **Safe filenames**  
  Removes weird characters and limits length so nothing breaks.

- **Unique names**  
  Auto-renames duplicates (`file.txt`, `file_1.txt`, etc).

- **Dry run mode**  
  See what would be extracted without writing anything.

- **Recursive search**  
  Look inside subfolders for ZIPs.

- **Verbose or quiet**  
  Show every file as it’s extracted, or stay silent except for summary.

- **Error logging**  
  All permission issues, bad ZIPs, etc. go into `extract_flat.log`.

---

## 🚀 Requirements

- Python **3.10** or newer  
- No extra libraries—only uses Python’s standard library.

---

## 🔧 Installation

1. Clone your repo (or download the code):  
   ```bash
   git clone https://github.com/your-username/Inkstract.git
   cd Inkstract
   ```

2. Make sure you’ve got Python 3.10+ installed:  
   ```bash
   python3 --version
   ```

---

## 📖 Usage

```bash
./inkstract.py [OPTIONS] <zip_folder> <output_folder>
```

| Option            | What it does                                      |
|-------------------|----------------------------------------------------|
| `-e, --exts`      | Comma-separated extensions to keep (e.g. `.png,.pdf`) |
| `-p, --patterns`  | Comma-separated glob patterns (e.g. `*.jpg,*.docx`)   |
| `--dry-run`       | Don’t write any files—just list what would happen  |
| `-r, --recursive` | Search subfolders for ZIPs                        |
| `-v, --verbose`   | Print each file as it’s extracted                 |
| `-q, --quiet`     | Suppress per-file messages (only summary at end)  |

### Examples

1. **Extract everything** from `zips/` into `out/`:
   ```bash
   ./inkstract.py zips/ out/
   ```

2. **Only pull images** (`.jpg` & `.png`):
   ```bash
   ./inkstract.py -e .jpg,.png zips/ out/
   ```

3. **Dry run** to see what would happen:
   ```bash
   ./inkstract.py --dry-run zips/ out/
   ```

4. **Recursive** search + verbose output:
   ```bash
   ./inkstract.py -r -v zips/ out/
   ```

5. **Using glob patterns** instead of extensions:
   ```bash
   ./inkstract.py -p '*.docx,*.pdf' zips/ out/
   ```

---

## 🛠️ Troubleshooting

- **“Error: Python 3.10 or higher is required.”**  
  You need to run with a newer Python version.

- **Permission errors** in the log?  
  Check you have write access to the output folder.

- **No files extracted?**  
  • Make sure your ZIP folder path is correct.  
  • If you used `-e/--exts` or `-p/--patterns`, double-check your filters.  

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).  

---

Happy inkstracting! 🦑✨
