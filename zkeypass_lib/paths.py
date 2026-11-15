"""All filesystem locations used by ZKeypass.

Two layouts, one rule: the program and everything it writes stay together.

A build, as made by build.bat, is one ZKeypass folder holding one file and
two folders:

    ZKeypass.exe          the launcher
    apps_files\\         the program files, replaced by every new build
    data\\               settings, backups, exports and temporary files

A build never ships anything in its data folder, so copying a new build over
an older one keeps the settings and any databases kept in data.  Builds
before this layout kept data inside the program folder (ZKeypass\\data\\);
the first start of a newer build moves it out, see migrate_old_build_data.

From source, the same data folder sits beside zkeypass.py:

    zkeypass.py, zkeypass_lib\\, libs\\, wordlists\\   the program
    data\\                                       what it writes

Nothing is ever written to the user profile, the registry, or the system
temp directory.
"""

import os
import shutil
import sys

FROZEN = bool(getattr(sys, "frozen", False))

if FROZEN:
    # PyInstaller puts the program files in apps_files beside ZKeypass.exe
    # (contents_directory in zkeypass.spec); data sits beside both.
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
    APP_DIR = os.path.abspath(getattr(
        sys, "_MEIPASS", os.path.join(ROOT_DIR, "apps_files")))
    DATA_DIR = os.path.join(ROOT_DIR, "data")
else:
    # .../ZKeypass/zkeypass_lib/paths.py -> .../ZKeypass
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    APP_DIR = ROOT_DIR
    DATA_DIR = os.path.join(ROOT_DIR, "data")

# Where new databases, copies and file dialogs start.  Older code calls this
# the program folder; it is the data folder now.
BASE_DIR = DATA_DIR

# Read-only parts of the program.
WORDLIST_DIR = os.path.join(APP_DIR, "wordlists")
LANG_DIR = os.path.join(APP_DIR, "lang")
LIBS_DIR = os.path.join(APP_DIR, "libs")

# Everything ZKeypass writes.
TMP_DIR = os.path.join(DATA_DIR, "_tmp")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")

SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
DEFAULT_VAULT_FILE = os.path.join(DATA_DIR, "default.kdbx")
LEGACY_VAULT_FILE = os.path.join(DATA_DIR, "default.zkp")

# The launcher a browser starts for native messaging.
LAUNCHER = (os.path.abspath(sys.executable) if FROZEN
            else os.path.join(ROOT_DIR, "Run ZKeypass.bat"))


BACKUPS_KEPT = 10


def keep_backup(path, kept=BACKUPS_KEPT):
    """Copy a database into data\\backups before it is replaced.

    Only the newest copies of each database are kept.  An old backup opens
    with the old master password, so keeping every one forever would let a
    password you have since changed keep unlocking your data.
    """
    import time

    if not path or not os.path.isfile(path):
        return None
    name = os.path.basename(path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = os.path.join(BACKUP_DIR, f"{name}.{stamp}.bak")
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        with open(path, "rb") as source, open(target, "wb") as copy:
            copy.write(source.read())
    except OSError:
        return None
    prune_backups(name, kept)
    return target


def prune_backups(name, kept=BACKUPS_KEPT):
    """Delete all but the newest backups of one database file name."""
    prefix = name + "."
    try:
        found = sorted(item for item in os.listdir(BACKUP_DIR)
                       if item.startswith(prefix) and item.endswith(".bak")
                       and item[len(prefix):-4].replace("-", "").isdigit())
    except OSError:
        return
    for item in found[:-kept] if kept > 0 else found:
        try:
            os.remove(os.path.join(BACKUP_DIR, item))
        except OSError:
            pass


def ensure_dirs():
    """Create the data folder layout on first run."""
    migrate_old_build_data()
    for path in (DATA_DIR, TMP_DIR, BACKUP_DIR):
        os.makedirs(path, exist_ok=True)
    migrate_old_settings()


def _folder_has_files(folder):
    try:
        return bool(os.listdir(folder))
    except OSError:
        return False


def _rebase(value, old, new):
    """Point a stored path that lay inside the old data folder at the new one."""
    if isinstance(value, str):
        folded = os.path.normcase(value)
        prefix = os.path.normcase(old)
        if folded == prefix or folded.startswith(prefix + os.sep):
            return new + value[len(old):]
        return value
    if isinstance(value, list):
        return [_rebase(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _rebase(item, old, new) for key, item in value.items()}
    return value


def migrate_old_build_data():
    """Move a build's data out of the program folder, once.

    Builds before the apps_files layout kept data in ZKeypass\\data beside the
    program files.  When a newer build is pasted over such a copy, that data
    folder is moved to data beside ZKeypass.exe, and paths in settings.json
    that pointed into it (recent databases, last folder) follow it.  Nothing
    is merged: if the new data folder already holds files, nothing moves.
    """
    if not FROZEN:
        return
    old = os.path.join(ROOT_DIR, "ZKeypass", "data")
    if not _folder_has_files(old) or _folder_has_files(DATA_DIR):
        return
    try:
        if os.path.isdir(DATA_DIR):
            os.rmdir(DATA_DIR)
        shutil.move(old, DATA_DIR)
    except OSError:
        return
    try:
        import json

        with open(SETTINGS_FILE, encoding="utf-8") as handle:
            stored = json.load(handle)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as handle:
            json.dump(_rebase(stored, old, DATA_DIR), handle, indent=2)
    except (OSError, ValueError):
        pass


def migrate_old_settings():
    """Move settings.json from beside zkeypass.py into the data folder, once."""
    old = os.path.join(ROOT_DIR, "settings.json")
    if os.path.isfile(SETTINGS_FILE) or not os.path.isfile(old):
        return
    try:
        shutil.move(old, SETTINGS_FILE)
    except OSError:
        pass


def enforce_local_temp():
    """Point Python's and the C library's temp handling at our own folder.

    Must be called before any module that may create temporary files is
    imported, so the entry script does it as its very first job.
    """
    ensure_dirs()
    os.environ["TMP"] = TMP_DIR
    os.environ["TEMP"] = TMP_DIR
    os.environ["TMPDIR"] = TMP_DIR
    import tempfile

    tempfile.tempdir = TMP_DIR


def add_local_libs():
    """Make the bundled 'libs' folder importable before site-packages.

    A build carries its libraries inside the ZKeypass folder, so this only matters
    when running from source.
    """
    if FROZEN:
        return
    if os.path.isdir(LIBS_DIR) and LIBS_DIR not in sys.path:
        sys.path.insert(0, LIBS_DIR)
