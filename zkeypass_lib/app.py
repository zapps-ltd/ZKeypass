"""Application start-up: portable environment, the unlock loop, the tray.

The application object outlives the main window: Control L locks and goes
back to the start window, and with the notification area icon on ZKeypass can
stay there locked.  --startup is what Windows runs at sign-in (startup.py).
"""

import hashlib
import os
import shutil
import sys

from . import paths

# The portable environment must be set before wx or cryptography are imported,
# because both may consult the temp directory while loading their libraries.
paths.enforce_local_temp()
paths.add_local_libs()

import wx  # noqa: E402  (imported after the environment is fixed)

from .vault import PasswordPair  # noqa: E402

from .dialogs import (StartDialog, UnlockDialog,  # noqa: E402
                      VaultNewDialog, ask_yes_no)
from .gui import MainFrame  # noqa: E402
from .settings import (Settings, remember_folder,  # noqa: E402
                       remember_recent)
from .kdbx_vault import create_any, open_any  # noqa: E402
from . import speech, startup, theme  # noqa: E402
from . import lang  # noqa: E402


VAULT_SUFFIXES = (".zkp", ".kdbx")


def find_vaults():
    """Every database file sitting in the program folder, in a stable order."""
    found = []
    for root, _dirs, files in os.walk(paths.BASE_DIR):
        if os.path.basename(root) in ("libs", "backups", "_tmp", "exports",
                                      "__pycache__"):
            continue
        found += [os.path.join(root, name) for name in sorted(files)
                  if name.lower().endswith(VAULT_SUFFIXES)]
    found.sort(key=lambda item: (not item.lower().endswith(".kdbx"), item.lower()))
    return found


def portable_copy(source, folder=None, settings=None):
    """Copy a database into the program folder and return the new path."""
    folder = folder or paths.BASE_DIR
    os.makedirs(folder, exist_ok=True)
    source = os.path.abspath(source)
    target = os.path.join(folder, os.path.basename(source))
    if os.path.normcase(os.path.abspath(target)) == os.path.normcase(source):
        return target
    stem, suffix = os.path.splitext(os.path.basename(source))
    counter = 2
    while os.path.exists(target):
        target = os.path.join(folder, f"{stem} ({counter}){suffix}")
        counter += 1
    shutil.copy2(source, target)
    if settings is not None:
        remember_folder(settings, source)
        remember_recent(settings, target)
        settings.save()
    return target


def choose_vault(parent, settings):
    """Ask what to do at start-up: open, copy in, or create.

    Returns (path, password, keyfile).  The path is empty to quit.  The
    password is None when the password still has to be asked for, and is
    already known when the database has just been created.
    """
    return choose_vault_ex(parent, settings)[:3]


def choose_vault_ex(parent, settings):
    """choose_vault, plus whether the Quit button itself was chosen.

    Quit ends ZKeypass even when it sits in the notification area; Escape or
    closing the window only puts it back there.
    """
    while True:
        dialog = StartDialog(parent, settings)
        answer = dialog.ShowModal()
        action = dialog.action
        chosen = dialog.path
        dialog.Destroy()
        if answer != wx.ID_OK or action in ("quit", "cancel"):
            return "", None, None, answer == wx.ID_OK and action == "quit"
        if action == "open":
            if os.path.isfile(chosen):
                return chosen, None, None, False
            wx.MessageBox(lang.t(
                "errors", "is_no_longer_there",
                "{chosen} is no longer there.",
                chosen=chosen), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, parent)
            continue
        if action == "copy":
            try:
                copied = portable_copy(chosen, settings=settings)
            except OSError as error:
                wx.MessageBox(lang.t(
                    "errors", "the_file_could_not_be_copied",
                    "The file could not be copied into the program folder: "
                    "{error}",
                    error=error), "ZKeypass",
                              wx.OK | wx.ICON_ERROR, parent)
                continue
            wx.MessageBox(
                lang.t(
                    "errors", "a_copy_was_placed_at_zkeypass",
                    "A copy was placed at\n\n{copied}\n\nZKeypass will open "
                    "the copy. The original file is not changed.",
                    copied=copied), "ZKeypass",
                wx.OK | wx.ICON_INFORMATION, parent)
            return copied, None, None, False
        if action == "new":
            new_dialog = VaultNewDialog(parent)
            if new_dialog.ShowModal() != wx.ID_OK:
                new_dialog.Destroy()
                continue
            path, password, keyfile = new_dialog.result
            options = getattr(new_dialog, "options", {}) or {}
            new_dialog.Destroy()
            options.pop("challenge_response", None)
            options.pop("summary", None)
            try:
                create_any(path, password, keyfile, **options)
            except Exception as error:
                wx.MessageBox(lang.t(
                    "errors", "could_not_create_the_database",
                    "Could not create the database: {error}",
                    error=error), "ZKeypass",
                              wx.OK | wx.ICON_ERROR, parent)
                continue
            return path, password, keyfile, False


def unlock(parent, path):
    """Windows Hello when set up, else the master password, three tries."""
    from .quick_unlock import unlock_loop

    return unlock_loop(parent, path, UnlockDialog)


# Tests build the application without a real session: no tray icon left in
# the notification area, no single-instance lock and no start-up registry.
INTERACTIVE = True


class ZKeypassApp(wx.App):
    """The program: one main window at most, plus the tray icon.

    The main window comes and goes as databases are locked and unlocked; the
    application object and the tray icon stay until Quit.  Locking with
    Control L goes back to the start window; with the tray icon on, closing
    that window leaves ZKeypass locked in the notification area.
    """

    def load_language(self):
        """Load the interface language before any window is built.

        The setting names a folder in lang; empty means the language that
        matches Windows' own display language, or English.  Tests run with
        INTERACTIVE off and always get English, whatever Windows speaks."""
        code = self.settings.get("language") or ""
        if not INTERACTIVE:
            code = lang.DEFAULT_CODE
        elif not code:
            code = lang.match_system_language(
                [found for found, _name in lang.available(paths.LANG_DIR)],
                lang.system_locale_name())
        return lang.load(paths.LANG_DIR, code)

    def OnInit(self):
        self.SetAppName("ZKeypass")
        self.settings = Settings.load()
        self.load_language()
        self.main = None
        self.tray = None
        self.busy = False
        self.closing = False
        self.startup_mode = startup.STARTUP_ARGUMENT in sys.argv[1:]
        if INTERACTIVE and not hasattr(self, "instance"):
            self.instance = wx.SingleInstanceChecker(
                "ZKeypass-" + wx.GetUserId() + "-" +
                hashlib.sha256(os.path.normcase(paths.DATA_DIR).encode(
                    "utf-8")).hexdigest()[:16])
            if self.instance.IsAnotherRunning():
                if not self.startup_mode:
                    wx.MessageBox(
                        lang.t(
                            "errors", "zkeypass_is_already_running_find_it",
                            "ZKeypass is already running. Find it in the "
                            "notification area: press Windows+B, then the "
                            "arrow keys, and Enter on ZKeypass."), "ZKeypass", wx.OK | wx.ICON_INFORMATION)
                return False
        theme.install(self, self.settings)
        speech.set_mode(self.settings.get("announce_actions", "auto"))
        self.SetExitOnFrameDelete(False)
        self.host = wx.Frame(None, title="ZKeypass")
        self.host.Show(False)
        if INTERACTIVE:
            startup.sync(self.settings)
        self.update_tray()
        if self.startup_mode and self.tray is not None:
            self.start_at_signin()
            return True
        if self.open_database():
            return True
        self.shutdown(exit_loop=False)
        return False

    # ------------------------------------------------------------ the tray

    def update_tray(self):
        """Show or remove the tray icon to match the settings."""
        wanted = INTERACTIVE and bool(self.settings.get("tray_enabled", True)
                                      or self.startup_mode
                                      or self.settings.get("run_at_startup"))
        if wanted and self.tray is None:
            from .tray import Tray

            self.tray = Tray(self)
            if self.main is not None:
                self.tray.set_locked(False, self.main.database_name())
        elif not wanted and self.tray is not None:
            self.tray.close()
            self.tray = None

    def start_at_signin(self):
        """Started by Windows at sign-in: unlocked only when that is allowed."""
        if self.settings.get("startup_unlock"):
            vault, password, _reason = startup.open_sealed()
            if vault is not None:
                self.show_main(vault, password, hidden=True)
                return
        self.tray.set_locked(True)

    # ------------------------------------------------------- the database

    def open_database(self):
        """The start window, then the password.  True once a database is open."""
        if self.busy:
            return False
        self.busy = True
        try:
            path, chosen_password, chosen_keyfile, quit_asked = choose_vault_ex(
                self.host, self.settings)
            if quit_asked:
                wx.CallAfter(self.quit)
                return False
            if not path:
                return False
            if chosen_password is None:
                vault, password = unlock(self.host, path)
            else:
                password = PasswordPair(chosen_password, chosen_keyfile)
                try:
                    vault = open_any(path, chosen_password, chosen_keyfile, None)
                except Exception as error:
                    wx.MessageBox(str(error), "ZKeypass", wx.OK | wx.ICON_ERROR,
                                  self.host)
                    return False
            if vault is None:
                return False
            self.show_main(vault, password)
            return True
        finally:
            self.busy = False

    def show_main(self, vault, password, hidden=False):
        remember_recent(self.settings, vault.path or "")
        remember_folder(self.settings, vault.path or "")
        self.settings.save()
        main = MainFrame(vault, password, self.settings)
        self.main = main
        self.SetTopWindow(main)
        if self.tray is not None:
            self.tray.set_locked(False, main.database_name())
        if not hidden:
            theme.fade_in(main)
            main.Show()
            main.Raise()

    def on_main_closed(self, reason):
        """The main window has saved and closed: lock, or quit."""
        self.main = None
        if self.tray is not None:
            self.tray.set_locked(True)
        if self.closing or reason == "quit":
            self.shutdown()
            return
        if reason == "lock":
            if not self.open_database() and self.tray is None:
                self.shutdown()
            return
        if self.tray is None:
            self.shutdown()

    # -------------------------------------------- commands from the tray

    @staticmethod
    def modal_open():
        for window in wx.GetTopLevelWindows():
            if isinstance(window, wx.Dialog) and window.IsModal():
                return window
        return None

    def show(self):
        """Show ZKeypass: bring the window back, or unlock when locked."""
        dialog = self.modal_open()
        if dialog is not None:
            dialog.Raise()
            return
        if self.main is not None:
            self.main.restore()
        else:
            self.open_database()

    def open_settings(self):
        if self.modal_open() is not None:
            self.show()
            return
        if self.main is not None:
            self.main.restore()
            self.main.on_settings()
            return
        from .dialogs import SettingsDialog

        dialog = SettingsDialog(self.host, self.settings)
        if dialog.ShowModal() == wx.ID_OK:
            self.settings.save()
            self.apply_settings(self.host)
        dialog.Destroy()

    def apply_settings(self, parent):
        """After Settings: the start-up entry, the tray icon and the effects."""
        theme.set_effects(self.settings.get("visual_effects", True))
        speech.set_mode(self.settings.get("announce_actions", "auto"))
        problem = startup.sync(self.settings) if INTERACTIVE else ""
        if problem:
            wx.MessageBox(problem, "ZKeypass", wx.OK | wx.ICON_WARNING, parent)
        self.update_tray()

    def quit(self):
        """Quit ZKeypass completely, saving the open database first."""
        dialog = self.modal_open()
        if dialog is not None:
            dialog.Raise()
            wx.MessageBox(lang.t(
                "errors", "close_the_open_window_first_then",
                "Close the open window first, then quit."), "ZKeypass",
                          wx.OK | wx.ICON_INFORMATION, dialog)
            return
        self.closing = True
        if self.main is not None:
            self.main.close_reason = "quit"
            self.main.Close()
            return
        self.shutdown()

    def shutdown(self, exit_loop=True):
        if self.tray is not None:
            self.tray.close()
            self.tray = None
        try:
            self.host.Destroy()
        except Exception:
            pass
        if exit_loop:
            self.ExitMainLoop()


def main(argv=None):
    """Entry point.  --native-messaging turns the program into a browser host."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--native-messaging" in argv:
        return native_messaging_main(argv)
    if "--list-tools" in argv:
        return list_tools_main(argv)
    app = ZKeypassApp(False)
    app.MainLoop()
    return 0


def native_messaging_main(argv):
    """Serve the browser over standard input and output, running no window."""
    from . import browser

    path = ""
    for index, item in enumerate(argv):
        if item in ("--vault", "-v") and index + 1 < len(argv):
            path = argv[index + 1]
    if not path:
        sys.stderr.write("--native-messaging needs --vault FILE\n")
        return 2
    password = os.environ.get("ZKEYPASS_NATIVE_PASSWORD", "")
    if not password:
        sys.stderr.write("Set ZKEYPASS_NATIVE_PASSWORD so the host can unlock "
                         "the database.  The browser never sees it.\n")
        return 2
    try:
        vault = open_any(path, password, None, None)
    except Exception as error:
        sys.stderr.write(f"Could not open {path}: {error}\n")
        return 2
    browser.native_messaging_loop(vault, password)
    return 0


def list_tools_main(argv):
    """Report which optional helpers are available on this machine."""
    from . import autotype, yubikey

    lines = [f"ZKeypass program {paths.APP_DIR}", f"ZKeypass data {paths.DATA_DIR}"]
    lines.append(f"Python {sys.version.split()[0]}")
    try:
        import wx

        lines.append(f"wxPython {wx.version()}")
    except Exception as error:
        lines.append(f"wxPython missing: {error}")
    try:
        import cryptography

        lines.append(f"cryptography {cryptography.__version__}")
    except Exception as error:
        lines.append(f"cryptography missing: {error}")
    lines.append(f"Key injection available: {autotype.available()}")
    lines.append(f"Security key support available: {yubikey.available()}")
    for line in yubikey.describe_keys() or ["No security key found."]:
        lines.append(line)
    text = "\n".join(lines) + "\n"
    if sys.stdout is None:
        # A windowed build has no console to print to; leave the report in
        # the data folder instead.
        with open(os.path.join(paths.DATA_DIR, "tools-report.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write(text)
        return 0
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
