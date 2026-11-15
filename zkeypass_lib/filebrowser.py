"""Choosing files and folders with Windows' own Open, Save and folder dialogs.

ZKeypass used to draw its own file browser.  It is gone: the standard Windows
dialogs are what NVDA and JAWS users already know, and they reach every drive,
network place and USB stick.  In the Open and Save dialogs the File name box
(Alt+N) takes a full path, or a folder, and Enter goes there.

The functions keep the names and arguments the rest of the program already
uses, so no caller had to change:

* choose_file()       any file, a file to save, or a folder (folder_mode)
* choose_database()   a .kdbx or .zkp, starting in the folder last used
* ask_for_database()  the same, returning only the path

Nothing here writes to disk except remembering the folder last used in
settings.json.
"""

import os

import wx

from . import paths
from . import lang


DATABASE_WILDCARD = ("KeePass database (*.kdbx)|*.kdbx|"
                     "ZKeypass database (*.zkp)|*.zkp|"
                     "All files (*.*)|*.*")
KEYFILE_WILDCARD = ("Key files (*.keyx;*.key;*.txt)|*.keyx;*.key;*.txt|"
                    "All files (*.*)|*.*")
ANY_WILDCARD = "All files (*.*)|*.*"

SUFFIXES = (".zkp", ".kdbx")


def build_filter(wildcard=DATABASE_WILDCARD, kinds=None, default_kind=""):
    """The filter text for the Windows dialog, plus what each choice means.

    Returns (spec, names, patterns, index): spec is the wx wildcard string,
    names and patterns list each filter in order, and index is the filter to
    show first.  A kinds dictionary, {name: "*.ext"}, wins over the wildcard.
    """
    pairs = []
    if kinds:
        for name, pattern in dict(kinds).items():
            pairs.append((str(name), str(pattern or "*.*")))
    else:
        parts = (wildcard or ANY_WILDCARD).split("|")
        for position in range(0, len(parts) - 1, 2):
            pairs.append((parts[position], parts[position + 1]))
    if not pairs:
        pairs = [("All files (*.*)", "*.*")]
    names = [name for name, _pattern in pairs]
    patterns = [pattern for _name, pattern in pairs]
    spec = "|".join(f"{name}|{pattern}" for name, pattern in pairs)
    index = names.index(default_kind) if default_kind in names else 0
    return spec, names, patterns, index


def add_extension(path, pattern):
    """Give a typed save name the filter's ending when it has none.

    Only a filter with a single ending, such as *.kdbx, adds one; *.* and
    lists such as *.keyx;*.key leave the name as typed.
    """
    if not path or os.path.splitext(os.path.basename(path))[1]:
        return path
    endings = [part.strip() for part in (pattern or "").split(";")
               if part.strip().startswith("*.") and part.strip() != "*.*"]
    if len(endings) != 1:
        return path
    return path + endings[0][1:]


def start_folder(default_dir=""):
    """The folder a dialog opens in: the one asked for, or the data folder."""
    if default_dir and os.path.isdir(default_dir):
        return os.path.abspath(default_dir)
    return paths.BASE_DIR


def choose_file(parent=None, title=None, default_dir="",
                default_name="", wildcard=DATABASE_WILDCARD, save=False,
                kinds=None, default_kind="", folder_mode=False):
    """Show the Windows dialog and return (path, kind).

    The path is empty when the user cancels.  kind is the name of the filter
    chosen when a kinds dictionary was given, otherwise default_kind.  With
    folder_mode the Windows folder picker is shown and a folder comes back.
    """
    if title is None:
        title = lang.t("dialogs", "open_a_file", "Open a file")
    folder = start_folder(default_dir)
    if folder_mode:
        with wx.DirDialog(parent, title, folder,
                          style=wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST) as dialog:
            if dialog.ShowModal() != wx.ID_OK:
                return "", ""
            chosen = dialog.GetPath()
        return (os.path.abspath(chosen) if chosen else ""), ""

    spec, names, patterns, index = build_filter(wildcard, kinds, default_kind)
    if save:
        style = wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT
    else:
        style = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
    with wx.FileDialog(parent, title, folder, default_name or "", spec,
                       style) as dialog:
        dialog.SetFilterIndex(index)
        if dialog.ShowModal() != wx.ID_OK:
            return "", ""
        chosen = dialog.GetPath()
        picked = dialog.GetFilterIndex()
    if not chosen:
        return "", ""
    if not 0 <= picked < len(names):
        picked = index
    if save:
        chosen = add_extension(chosen, patterns[picked])
    kind = names[picked] if kinds else default_kind
    return os.path.abspath(chosen), kind


def choose_database(parent=None, settings=None, save=False,
                    default_name="", title=None,
                    kinds=None, default_kind="KeePass database (.kdbx)"):
    """Choose a database, starting in the folder last used and remembering it."""
    folder = ""
    if settings is not None:
        folder = settings.get("last_folder") or ""
    if title is None:
        title = lang.t(
            "dialogs", "save_the_database_as",
            "Save the database as") if save else lang.t(
            "dialogs", "open_a_database",
            "Open a database")
    path, kind = choose_file(parent, title=title, default_dir=folder,
                             default_name=default_name,
                             wildcard=DATABASE_WILDCARD, save=save,
                             kinds=kinds, default_kind=default_kind)
    if path and settings is not None:
        try:
            from .settings import remember_folder

            remember_folder(settings, path)
            remember_recent_folder(settings, os.path.dirname(path))
            settings.save()
        except Exception:
            pass
    return path, kind


def remember_recent_folder(settings, folder, limit=8):
    """Keep a short list of folders, most recent first, inside settings."""
    folder = os.path.abspath(folder or "")
    if not folder or not os.path.isdir(folder):
        return
    recent = [str(item) for item in (settings.get("recent_folders") or [])]
    recent = [item for item in recent
              if os.path.normcase(item) != os.path.normcase(folder)]
    recent.insert(0, folder)
    settings["recent_folders"] = recent[:limit]


def ask_for_database(parent=None, settings=None, save=False,
                     default_name="", kinds=None, default_kind="",
                     title=None):
    """The one call the rest of the program uses to pick a database file."""
    path, _kind = choose_database(parent, settings, save=save,
                                  default_name=default_name, title=title,
                                  kinds=kinds, default_kind=default_kind)
    return path
