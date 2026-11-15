"""Dialogs: unlock, create, entry editor, generator, settings, reports, SSH.

Every dialog is ordinary wx widgets so screen readers handle navigation,
labelling and value reading with no custom drawing anywhere.
"""

import datetime
import os
import time

import wx
import wx.adv

from . import filebrowser, health, paths, totp
from . import autotype_store, passkeys as passkeylib
from . import lang


_SEQUENCE_PRESETS = (
    ("Username, Tab, Password, Enter", "{USERNAME}{TAB}{PASSWORD}{ENTER}"),
    ("Username, Tab, Password", "{USERNAME}{TAB}{PASSWORD}"),
    ("Password only, Enter", "{PASSWORD}{ENTER}"),
    ("Username only, Tab", "{USERNAME}{TAB}"),
    ("Verification code only", "{TOTP}{ENTER}"),
    ("Select all first, then fill", "{CLEARFIELD}{USERNAME}{TAB}{PASSWORD}{ENTER}"),
)


def ask_yes_no(parent, message, caption="ZKeypass"):
    return wx.MessageBox(message, caption,
                         wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION,
                         parent) == wx.YES


def _copy_secret(window, text, what=""):
    """Copy a secret the way the main window does: out of history, cleared.

    what names the secret, "Password" or "Code", and is said aloud.
    """
    from . import clipboard, speech
    from .settings import Settings

    frame = wx.GetTopLevelParent(window).GetParent() if window else None
    settings = getattr(frame, "settings", None) or Settings.load()
    seconds = int(settings.get("clipboard_clear_seconds") or 0)
    if clipboard.copy_secret(text, seconds):
        message = lang.t(
            "dialogs", "copied",
            "{what} copied.",
            what=what or lang.t("dialogs", "text", "Text"))
        if seconds:
            message += lang.t(
                "dialogs", "clipboard_clears_in_seconds",
                " Clipboard clears in {seconds} seconds.",
                seconds=seconds)
    else:
        message = lang.t(
            "dialogs", "could_not_open_the_clipboard",
            "Could not open the clipboard.")
    if window is not None and window.IsShown():
        speech.speak(message, window=window)


class _NamedAccessible(getattr(wx, "Accessible", object)):
    """Gives a control a fixed name for NVDA, JAWS and Narrator."""

    def __init__(self, window, name):
        super().__init__(window)
        self._name = name

    def GetName(self, child_id):
        if child_id == 0:
            return (wx.ACC_OK, self._name)
        return (wx.ACC_NOT_IMPLEMENTED, "")


def name_for_screen_readers(control, name):
    """Name a control whose caption was not created just before it.

    Buttons and check boxes already say their own text, so they are left
    alone.  Where wx has no accessibility support, nothing happens.
    """
    if isinstance(control, (wx.Button, wx.CheckBox)) or not hasattr(wx, "Accessible"):
        return
    try:
        control.SetAccessible(_NamedAccessible(control, name))
    except Exception:
        pass


class ReadOnlyField(wx.TextCtrl):
    """A read-only text box that Tab still reaches.

    wxWidgets leaves read-only one-line boxes out of the Tab order, so a
    keyboard user could never get to a password shown for reading, a
    generated password or the current code.  This one stays a Tab stop.
    """

    def AcceptsFocusFromKeyboard(self):
        return self.IsShown() and self.IsEnabled()


def labelled(parent):
    """Flex grid sizer plus helper for caption and control rows."""
    grid = wx.FlexGridSizer(cols=2, vgap=8, hgap=10)
    grid.AddGrowableCol(1, 1)

    def add(caption, control):
        """Add one row: the caption, then its control.

        Windows names a field after the text created just before it, so the
        caption is created first.  Pass the control as a lambda that builds
        it, add("Name", lambda: wx.TextCtrl(parent)), and the order is right
        by itself.  A control built earlier is named for screen readers
        through its accessible name instead, and no window is ever moved,
        so the Tab order stays exactly the order things were built in.
        """
        label = wx.StaticText(parent, label=caption)
        if isinstance(control, wx.Window):
            name_for_screen_readers(control, caption)
        else:
            control = control()
        control.SetName(caption)
        grid.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(control, 1, wx.EXPAND)
        return control

    return grid, add



def choose_folder(parent, caption, default_dir="", allow_none=True):
    """Pick a folder with the program's own browser, keyboard only.

    The browser lists folders and files; choosing a folder is done by pressing
    the "This folder" button or simply entering a folder and pressing Open with
    no file name, which returns the folder that is open.
    """
    path, _kind = filebrowser.choose_file(
        parent, title=caption, default_dir=default_dir or paths.BASE_DIR,
        wildcard=filebrowser.ANY_WILDCARD, folder_mode=True)
    if not path:
        return ""
    if allow_none and not os.path.isdir(path):
        # A file was picked; use its folder, which is what a folder chooser means.
        folder = os.path.dirname(path)
        return folder if os.path.isdir(folder) else ""
    return path


def make_key_file(parent, field):
    """Create a new KeePass key file and put its path in the given field."""
    from .kdbx import write_key_file

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "create_a_key_file",
            "Create a key file"), default_dir=paths.BASE_DIR,
        default_name="new-key.keyx",
        wildcard="Key files (*.keyx)|*.keyx|All files (*.*)|*.*", save=True)
    if not path:
        return
    if not path.lower().endswith((".keyx", ".key")):
        path += ".keyx"
    try:
        write_key_file(path)
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_write_the_key_file",
            "Could not write the key file: {error}",
            error=error), "ZKeypass",
                      wx.OK | wx.ICON_ERROR, parent)
        return
    field.SetValue(path)
    wx.MessageBox(
        lang.t(
            "errors", "the_key_file_has_been_created",
            "The key file has been created. Keep a copy of it somewhere "
            "safe: without it the database cannot be opened."),
        "ZKeypass", wx.OK | wx.ICON_INFORMATION, parent)


class StartDialog(wx.Dialog):
    """The first window: open, copy in, create, or quit.

    Startup never goes straight to a password box.  Everything is an ordinary
    named control, and the database is chosen with the program's own file
    browser, which can reach every drive by keyboard alone.
    """

    def __init__(self, parent, settings=None, suggested=""):
        super().__init__(parent, title=lang.t(
            "dialogs", "zkeypass_choose_a_database",
            "ZKeypass - choose a database"),
                         size=(720, 700))
        self.settings = settings
        # "cancel" is Escape or the close box: back to the notification area
        # when ZKeypass sits there.  The Quit button sets "quit", which ends it.
        self.action = "cancel"
        self.path = ""

        from .theme import Banner

        banner = Banner(self, lang.t(
            "dialogs", "offline_password_vault_nothing_leaves_this",
            "Offline password vault  ·  nothing leaves this computer"))
        heading = wx.StaticText(
            self, label=lang.t(
                "dialogs", "welcome_to_zkeypass_an_offline_password",
                "Welcome to ZKeypass, an offline password manager."))
        font = heading.GetFont()
        font.MakeBold()
        heading.SetFont(font)

        explanation = wx.StaticText(
            self, label=(
                lang.t(
                    "dialogs", "open_a_database_reads_an_existing",
                    "Open a database reads an existing KeePass file (.kdbx) "
                    "or ZKeypass database (.zkp) from anywhere on this "
                    "computer. Keep a portable copy beside the program "
                    "copies one into this folder. Create a new database "
                    "starts an empty one. Every command here has a key on "
                    "the button label: press Alt and the underlined letter, "
                    "or Tab between the buttons and press Enter.")))
        explanation.Wrap(670)

        recent_label = wx.StaticText(self, label=lang.control_label(
            "recent_databases_2",
            "&Recent databases"))
        self.recent_list = wx.ListBox(self, size=(-1, 170))
        self.recent_list.SetName(lang.t(
            "dialogs", "recent_databases",
            "Recent databases"))
        self.recent_list.Bind(wx.EVT_LISTBOX_DCLICK, self.on_recent_activated)
        # A dialog takes Enter for its own default button before a list box
        # ever sees it, so Enter on the list is caught here, ahead of that.
        self.Bind(wx.EVT_CHAR_HOOK, self.on_recent_key)

        self.open_button = wx.Button(self, label=lang.control_label(
            "open_a_database_2",
            "&Open a database..."))
        self.copy_button = wx.Button(self, label=lang.control_label(
            "keep_a_portable_copy",
            "Keep a portable cop&y..."))
        self.new_button = wx.Button(self, label=lang.control_label(
            "create_a_new_database_2",
            "&Create a new database..."))
        self.browse_button = wx.Button(
            self, label=lang.control_label(
                "browse_this_computer_for_a_database_2",
                "&Browse this computer for a database file..."))
        quit_button = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "quit_2",
            "&Quit"))
        self.open_button.SetName(lang.t(
            "dialogs", "open_a_database",
            "Open a database"))
        self.copy_button.SetName(lang.t(
            "dialogs", "keep_a_portable_copy_in_this",
            "Keep a portable copy in this folder"))
        self.new_button.SetName(lang.t(
            "dialogs", "create_a_new_database",
            "Create a new database"))
        self.browse_button.SetName(lang.t(
            "dialogs", "browse_this_computer_for_a_database",
            "Browse this computer for a database file"))
        quit_button.SetName(lang.t("dialogs", "quit", "Quit"))
        self.open_button.Bind(wx.EVT_BUTTON, self.on_open)
        self.copy_button.Bind(wx.EVT_BUTTON, self.on_copy)
        self.new_button.Bind(wx.EVT_BUTTON, self.on_new)
        self.browse_button.Bind(wx.EVT_BUTTON, self.on_browse_only)
        quit_button.Bind(wx.EVT_BUTTON, lambda event: self.finish("quit", ""))

        self.status = wx.StaticText(self, label="")
        self.status.SetName(lang.t(
            "dialogs", "what_to_do_here",
            "What to do here"))
        self.status.Wrap(670)

        buttons = wx.BoxSizer(wx.VERTICAL)
        for button in (self.open_button, self.copy_button, self.new_button,
                       self.browse_button, quit_button):
            buttons.Add(button, 0, wx.EXPAND | wx.BOTTOM, 6)

        body = wx.BoxSizer(wx.HORIZONTAL)
        left = wx.BoxSizer(wx.VERTICAL)
        left.Add(recent_label, 0, wx.BOTTOM, 4)
        left.Add(self.recent_list, 1, wx.EXPAND)
        body.Add(left, 1, wx.EXPAND | wx.RIGHT, 12)
        body.Add(buttons, 0)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(banner, 0, wx.EXPAND)
        root.Add(heading, 0, wx.ALL, 12)
        root.Add(explanation, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        root.Add(body, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 12)
        root.Add(self.status, 0, wx.EXPAND | wx.ALL, 12)
        self.SetSizer(root)

        self.refresh_recent()
        if suggested:
            self.status.SetLabel(lang.t(
                "dialogs", "starting_with",
                "Starting with {suggested}.",
                suggested=suggested))
            self.on_open_path(suggested)
            return
        if self.recent_paths_cache:
            self.recent_list.SetSelection(0)
            self.focus(self.recent_list)
            self.status.SetLabel(lang.t(
                "dialogs", "press_enter_on_a_database_in",
                "Press Enter on a database in the list to open it, or Tab to "
                "the buttons."))
        else:
            self.focus(self.browse_button)
            self.status.SetLabel(
                lang.t(
                    "dialogs", "no_database_has_been_used_yet",
                    "No database has been used yet on this computer. Press "
                    "Enter on Browse this computer for a database file to "
                    "pick one in the Windows Open dialog, or Tab to Create a "
                    "new database."))

    # ------------------------------------------------------------- recent list

    def focus(self, control):
        """Set focus only when the window is really on screen.

        Building a dialog off screen, as the headless tests do, cannot take
        focus and Windows says so, so this stays quiet in that case.
        """
        try:
            if self.IsShown():
                control.SetFocus()
        except Exception:
            pass

    def recent_paths(self):
        found = []
        for path in (self.settings.get("recent_vaults") or []) if self.settings else []:
            if os.path.isfile(path):
                found.append(path)
        last = (self.settings.get("last_vault") or "") if self.settings else ""
        if last and os.path.isfile(last) and last not in found:
            found.insert(0, last)
        return found

    def refresh_recent(self):
        self.recent_list.Clear()
        self.recent_paths_cache = self.recent_paths()
        for path in self.recent_paths_cache:
            kind = lang.t("dialogs", "keepass_database", "KeePass database") if path.lower().endswith(".kdbx") \
                else lang.t("dialogs", "zkeypass_database", "ZKeypass database")
            self.recent_list.Append(f"{os.path.basename(path)}  ({kind})  {path}")
        if not self.recent_paths_cache:
            self.recent_list.Append(lang.menu_label(
                "no_databases_used_yet",
                "No databases used yet"))
            self.recent_list.Enable(False)

    def selected_recent(self):
        if not self.recent_paths_cache:
            return ""
        index = self.recent_list.GetSelection()
        if 0 <= index < len(self.recent_paths_cache):
            return self.recent_paths_cache[index]
        return ""

    def on_recent_activated(self, event):
        path = self.selected_recent()
        if path:
            self.finish("open", path)

    def on_recent_key(self, event):
        code = event.GetKeyCode()
        if code == ord("Q") and event.ControlDown() and event.ShiftDown():
            self.finish("quit", "")
            return
        if code == wx.WXK_ESCAPE:
            self.finish("cancel", "")
            return
        if (code in (wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER)
                and wx.Window.FindFocus() is self.recent_list):
            path = self.selected_recent()
            if path:
                self.finish("open", path)
                return
        event.Skip()

    # ---------------------------------------------------------------- actions

    def browse(self, caption):
        """Always opens the file browser itself.  Never the recent list."""
        return filebrowser.ask_for_database(self, self.settings, title=caption)

    def on_open(self, event):
        """Open the highlighted recent database, or browse when there is none."""
        path = self.selected_recent()
        if not path:
            path = self.browse(lang.t(
                "dialogs", "open_a_database",
                "Open a database"))
        if path:
            self.finish("open", path)

    def on_browse_only(self, event):
        """Browse this computer, whatever the recent list holds."""
        path = self.browse(lang.t(
            "dialogs", "browse_for_a_database_file",
            "Browse for a database file"))
        if path:
            self.finish("open", path)

    def on_copy(self, event):
        path = self.selected_recent()
        if not path:
            path = self.browse(lang.t(
                "dialogs", "choose_a_database_to_copy_into",
                "Choose a database to copy into this folder"))
        if path:
            self.finish("copy", path)

    def on_new(self, event):
        self.finish("new", "")

    def on_open_path(self, path):
        self.finish("open", path)

    def finish(self, action, path):
        self.action = action
        self.path = path
        if self.IsModal():
            self.EndModal(wx.ID_CANCEL if action == "cancel" else wx.ID_OK)
        else:
            # Built without showing it, as the tests do: record and go quiet.
            self.Hide()


class UnlockDialog(wx.Dialog):
    def __init__(self, parent, path):
        super().__init__(parent, title=lang.t(
            "dialogs", "unlock_database",
            "Unlock database"), size=(560, 380))
        self.path = path
        self.password = ""
        self.challenge_response = None
        self.hardware_slot = None
        self.public_header = {}
        if str(path).lower().endswith(".kdbx"):
            from .kdbx import read_public_header_of_file

            self.public_header = read_public_header_of_file(path)
            recorded = str(self.public_header.get("public_custom_data", {})
                           .get("ZKeypass YubiKey", "") or "")
            if recorded.isdigit():
                self.hardware_slot = int(recorded)
        from .theme import Banner

        banner = Banner(self, lang.t(
            "dialogs", "locked",
            "Locked  ·  {basename}",
            basename=os.path.basename(path)), locked=True)
        grid, add = labelled(self)
        add(lang.t("dialogs", "database_file", "Database file"), lambda: wx.StaticText(self, label=os.path.basename(path)))
        self.password_field = add(lang.t(
            "dialogs", "master_password",
            "Master password"),
                                  lambda: wx.TextCtrl(self, style=wx.TE_PASSWORD))
        self.keyfile_field = add(lang.t(
            "dialogs", "key_file_or_leave_blank",
            "Key file (or leave blank)"),
                                 lambda: wx.TextCtrl(self))
        browse = add(lang.t(
            "dialogs", "choose_a_key_file",
            "Choose a key file"),
                     lambda: wx.Button(self, label=lang.control_label(
                         "choose_key_file",
                         "&Choose key file...")))
        browse.Bind(wx.EVT_BUTTON, self.on_browse_keyfile)
        from . import quick_unlock, winhello

        if winhello.is_set_up(path):
            hello = add(lang.t("dialogs", "windows_hello", "Windows Hello"),
                        lambda: wx.Button(self, label=lang.control_label(
                            "use_windows_hello_instead",
                            "Use &Windows Hello instead")))
            hello.Bind(wx.EVT_BUTTON,
                       lambda event: self.EndModal(quick_unlock.ID_USE_HELLO))
        self.hardware_check = add(
            lang.t(
                "dialogs", "also_require_the_security_key",
                "Also require the security key"),
            lambda: wx.CheckBox(self, label=lang.control_label(
                "use_the_security_key",
                "&Use the security key")))
        if self.hardware_slot:
            self.hardware_check.SetValue(True)
        self.slot_choice = add(lang.t(
            "dialogs", "security_key_slot",
            "Security key slot"),
                               lambda: wx.Choice(self, choices=[lang.t(
                                   "dialogs", "slot_1_long_press",
                                   "Slot 1, long press"),
                                                        lang.t(
                                                            "dialogs", "slot_2_short_press",
                                                            "Slot 2, short press")]))
        self.slot_choice.SetSelection((self.hardware_slot or 1) - 1)
        self.summary = add(lang.t("dialogs", "encryption", "Encryption"), lambda: ReadOnlyField(
            self, style=wx.TE_READONLY))
        self.summary.SetValue(self.describe_cryptography())
        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(banner, 0, wx.EXPAND)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizer(root)
        self.SetSize(self.FromDIP(wx.Size(560, 460)))
        self.password_field.SetFocus()
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)
        self.Bind(wx.EVT_TEXT_ENTER, self.on_ok, self.password_field)

    def on_browse_keyfile(self, event):
        """Pick a key file with the same keyboard-friendly browser."""
        path, _kind = filebrowser.choose_file(
            self, title=lang.t(
                "dialogs", "choose_a_key_file",
                "Choose a key file"), default_dir=paths.BASE_DIR,
            wildcard=filebrowser.KEYFILE_WILDCARD)
        if path:
            self.keyfile_field.SetValue(path)

    @property
    def keyfile(self):
        return self.keyfile_field.GetValue().strip() or None

    def describe_cryptography(self):
        """A sentence naming the cipher and the key derivation function."""
        header = self.public_header or {}
        if not header:
            return lang.t(
                "dialogs", "zkeypass_database_aes_256_gcm_with",
                "ZKeypass database, AES-256-GCM with Argon2id.")
        from .kdbx import CIPHER_LABELS, KDF_LABELS

        cipher = CIPHER_LABELS.get(header.get("cipher"), header.get("cipher"))
        kdf = KDF_LABELS.get(header.get("kdf"), header.get("kdf"))
        version = int(header.get("format_version") or 0)
        family = "KDBX 4" if version >= 0x00040000 else "KDBX 3.1"
        return f"{family}, {cipher}, {kdf}."

    def use_hardware_key(self):
        return bool(self.hardware_check.GetValue())

    def slot(self):
        return 1 if self.slot_choice.GetSelection() <= 0 else 2

    def on_ok(self, event):
        self.password = self.password_field.GetValue()
        if not self.password and not self.keyfile and not self.use_hardware_key():
            wx.MessageBox(lang.t(
                "errors", "enter_the_master_password_or_choose",
                "Enter the master password or choose a key file."),
                          "ZKeypass", wx.OK | wx.ICON_WARNING, self)
            return
        if self.keyfile and not os.path.isfile(self.keyfile):
            wx.MessageBox(lang.t(
                "errors", "that_key_file_does_not_exist",
                "That key file does not exist."), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        if self.use_hardware_key():
            from . import yubikey

            slot = self.slot()
            try:
                self.challenge_response = yubikey.challenge_response(
                    b"ZKPass master key", slot)
            except yubikey.YubiKeyError as error:
                wx.MessageBox(str(error), lang.t(
                    "dialogs", "security_key",
                    "Security key"),
                              wx.OK | wx.ICON_ERROR, self)
                return
            except OSError as error:
                wx.MessageBox(lang.t(
                    "errors", "the_security_key_could_not_be",
                    "The security key could not be reached: {error}",
                    error=error),
                              lang.t("dialogs", "security_key", "Security key"), wx.OK | wx.ICON_ERROR, self)
                return
            self.hardware_slot = slot
        self.EndModal(wx.ID_OK)


class VaultNewDialog(wx.Dialog):
    def __init__(self, parent):
        super().__init__(parent, title=lang.t(
            "dialogs", "new_database",
            "New database"), size=(580, 470))
        self.result = ("", "", None)
        grid, add = labelled(self)
        self.format_choice = add(lang.t("dialogs", "format", "Format"), lambda: wx.Choice(
            self, choices=[lang.t(
                "dialogs", "keepass_database_opens_in_keepassxc_kdbx",
                "KeePass database, opens in KeePassXC (*.kdbx)"),
                           lang.t(
                               "dialogs", "zkeypass_database_zkeypass_only_zkp",
                               "ZKeypass database, ZKeypass only (*.zkp)")]))
        self.format_choice.SetSelection(0)
        self.format_choice.SetName(lang.t(
            "dialogs", "database_format",
            "Database format"))
        self.format_choice.Bind(wx.EVT_CHOICE, self.on_format)
        self.name_field = add(lang.t("dialogs", "file_name", "File name"), lambda: wx.TextCtrl(self, value="default.kdbx"))
        self.folder_field = add(lang.t("dialogs", "folder", "Folder"), lambda: wx.TextCtrl(self, value=paths.BASE_DIR))
        browse = wx.Button(self, label=lang.control_label(
            "browse",
            "&Browse..."))
        browse.Bind(wx.EVT_BUTTON, self.on_browse)
        self.keyfile_field = add(lang.t(
            "dialogs", "key_file_kdbx_only_optional",
            "Key file (kdbx only, optional)"),
                                 lambda: wx.TextCtrl(self))
        self.keyfile_field.SetName(lang.t("dialogs", "key_file", "Key file"))
        choose_key = add(lang.t(
            "dialogs", "create_a_key_file",
            "Create a key file"),
                         lambda: wx.Button(self, label=lang.control_label(
                             "create_key_file",
                             "&Create key file...")))
        choose_key.Bind(wx.EVT_BUTTON, self.on_create_keyfile)
        self.password_field = add(lang.t(
            "dialogs", "master_password",
            "Master password"),
                                  lambda: wx.TextCtrl(self, style=wx.TE_PASSWORD))
        self.confirm_field = add(lang.t(
            "dialogs", "repeat_master_password",
            "Repeat master password"),
                                 lambda: wx.TextCtrl(self, style=wx.TE_PASSWORD))
        from .kdbx import CIPHER_LABELS, CIPHER_CHOICES, KDF_CHOICES, KDF_LABELS

        self.cipher_choice = add(lang.t(
            "dialogs", "encryption_method",
            "Encryption method"), lambda: wx.Choice(
            self, choices=[CIPHER_LABELS[name] for name in CIPHER_CHOICES]))
        self.cipher_choice.SetSelection(0)
        self.kdf_choice = add(lang.t(
            "dialogs", "password_hardening",
            "Password hardening"), lambda: wx.Choice(
            self, choices=[KDF_LABELS[name] for name in KDF_CHOICES]))
        self.kdf_choice.SetSelection(0)
        self.cost_choice = add(lang.t(
            "dialogs", "unlock_strength",
            "Unlock strength"), lambda: wx.Choice(self, choices=[
            lang.t(
                "dialogs", "fast_for_testing_low_cost",
                "Fast for testing, low cost"),
            lang.t(
                "dialogs", "balanced_64_mib_and_five_passes",
                "Balanced, 64 MiB and five passes"),
            lang.t(
                "dialogs", "strong_256_mib_and_ten_passes",
                "Strong, 256 MiB and ten passes"),
        ]))
        self.cost_choice.SetSelection(1)
        self.hardware_check = add(
            lang.t(
                "dialogs", "require_the_security_key",
                "Require the security key"),
            lambda: wx.CheckBox(self, label=lang.control_label(
                "also_require_a_security_key",
                "Also require a security &key")))
        self.hint = wx.StaticText(
            self, label=lang.t(
                "dialogs", "a_long_passphrase_of_four_or",
                "A long passphrase of four or more words is stronger than a "
                "short complicated password."))
        self.hint.Wrap(480)
        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        root.Add(browse, 0, wx.LEFT | wx.RIGHT, 12)
        root.Add(self.hint, 0, wx.EXPAND | wx.ALL, 12)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizer(root)
        self.name_field.SetFocus()
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)

    def on_browse(self, event):
        chosen = choose_folder(self, lang.t(
            "dialogs", "choose_a_folder_for_the_database",
            "Choose a folder for the database"),
                               self.folder_field.GetValue())
        if chosen:
            self.folder_field.SetValue(chosen)

    def on_format(self, event=None):
        suffix = ".kdbx" if self.format_choice.GetSelection() == 0 else ".zkp"
        current = self.name_field.GetValue().strip() or "default"
        stem = os.path.splitext(current)[0] or "default"
        self.name_field.SetValue(stem + suffix)
        for control in (self.keyfile_field,):
            control.Enable(suffix == ".kdbx")

    def on_create_keyfile(self, event):
        make_key_file(self, self.keyfile_field)

    def on_ok(self, event):
        kdbx_format = self.format_choice.GetSelection() == 0
        default = "default.kdbx" if kdbx_format else "default.zkp"
        suffix = ".kdbx" if kdbx_format else ".zkp"
        name = self.name_field.GetValue().strip() or default
        if not name.lower().endswith((".kdbx", ".zkp")):
            name += suffix
        if kdbx_format and not name.lower().endswith(".kdbx"):
            name = os.path.splitext(name)[0] + ".kdbx"
        if not kdbx_format and not name.lower().endswith(".zkp"):
            name = os.path.splitext(name)[0] + ".zkp"
        folder = self.folder_field.GetValue().strip() or paths.BASE_DIR
        password = self.password_field.GetValue()
        if len(password) < 8:
            wx.MessageBox(lang.t(
                "errors", "choose_a_master_password_of_at",
                "Choose a master password of at least eight characters."),
                          "ZKeypass", wx.OK | wx.ICON_WARNING, self)
            return
        if password != self.confirm_field.GetValue():
            wx.MessageBox(lang.t(
                "errors", "the_two_master_passwords_do_not",
                "The two master passwords do not match."), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        keyfile = self.keyfile_field.GetValue().strip() or None
        if keyfile and not kdbx_format:
            wx.MessageBox(lang.t(
                "errors", "a_key_file_needs_the_keepass",
                "A key file needs the KeePass database format."),
                          "ZKeypass", wx.OK | wx.ICON_WARNING, self)
            return
        target = os.path.join(folder, name)
        if os.path.exists(target) and not ask_yes_no(
                self, lang.t(
                    "dialogs", "already_exists_replace_it",
                    "{target} already exists. Replace it?",
                    target=target)):
            return
        self.result = (target, password, keyfile)
        self.options = self.collect_options()
        self.EndModal(wx.ID_OK)

    def collect_options(self):
        """Everything the database needs, so the main window can create it."""
        from .kdbx import CIPHER_CHOICES, KDF_CHOICES, CIPHER_LABELS, KDF_LABELS

        cipher = CIPHER_CHOICES[max(0, self.cipher_choice.GetSelection())]
        kdf = KDF_CHOICES[max(0, self.kdf_choice.GetSelection())]
        cost = self.cost_choice.GetSelection()
        options = {"cipher": cipher, "kdf": kdf}
        if cost == 0:
            options.update({"memory_kib": 8192, "iterations": 1})
        elif cost == 2:
            options.update({"memory_kib": 262144, "iterations": 10})
        else:
            options.update({"memory_kib": 65536, "iterations": 5})
        if self.hardware_check.GetValue():
            options["challenge_response"] = True
        options["summary"] = (lang.t(
            "dialogs", "with",
            "{cipher} with {kdf}.",
            cipher=CIPHER_LABELS[cipher].split(',')[0],
            kdf=KDF_LABELS[kdf].split(',')[0]))
        return options


class AttachmentDropTarget(wx.FileDropTarget):
    """Lets files be dragged straight onto the stored files page."""

    def __init__(self, dialog, window):
        super().__init__()
        self.dialog = dialog
        self.window = window

    def OnDropFiles(self, x, y, paths):
        added = 0
        for path in paths:
            if os.path.isfile(path):
                self.dialog.add_attachment_path(path)
                added += 1
        if added:
            self.dialog.refresh_attachments()
            wx.Bell()
        return added > 0


class EntryDialog(wx.Dialog):
    """Notebook editor: general details, notes, TOTP, extra fields, files."""

    def __init__(self, parent, vault, entry_id=None):
        title = lang.t("dialogs", "edit_entry", "Edit entry") if entry_id else lang.t(
            "dialogs", "new_entry",
            "New entry")
        super().__init__(parent, title=title, size=(640, 620))
        self.vault = vault
        self.entry_id = entry_id
        self.entry = vault.get_entry(entry_id) if entry_id else {
            "title": "", "username": "", "password": "", "url": "", "notes": "",
            "totp_secret": "", "totp_digits": 6, "totp_period": 30,
            "totp_algorithm": "SHA1", "expires": 0, "favourite": 0,
            "group_id": None,
        }
        self.attributes = list(vault.attributes(entry_id)) if entry_id else []
        self.attachments = list(vault.attachments(entry_id)) if entry_id else []
        self.removed_attachments = []

        self.notebook = wx.Notebook(self)
        self.notebook.SetName(lang.t(
            "dialogs", "entry_sections",
            "Entry sections"))
        self._build_general()
        self._build_notes()
        self._build_totp()
        self._build_attributes()
        self._build_autotype()
        self._build_passkeys()
        self._build_attachments()

        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.notebook, 1, wx.EXPAND | wx.ALL, 8)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 8)
        self.SetSizer(root)
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)
        self.title_field.SetFocus()

    # ---------------------------------------------------------------- general

    def _build_general(self):
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.title_field = add(lang.t("dialogs", "title", "Title"), lambda: wx.TextCtrl(page))
        self.username_field = add(lang.t("dialogs", "username", "Username"), lambda: wx.TextCtrl(page))
        password_row = wx.BoxSizer(wx.HORIZONTAL)
        self.password_field = wx.TextCtrl(page, style=wx.TE_PASSWORD)
        self.password_field.SetName(lang.t("dialogs", "password", "Password"))
        reveal = wx.CheckBox(page, label=lang.control_label(
            "show_password",
            "&Show password"))
        reveal.Bind(wx.EVT_CHECKBOX, self.on_reveal)
        generate = wx.Button(page, label=lang.control_label(
            "generate",
            "&Generate..."))
        generate.Bind(wx.EVT_BUTTON, self.on_generate)
        password_row.Add(self.password_field, 1, wx.EXPAND | wx.RIGHT, 6)
        password_row.Add(reveal, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
        password_row.Add(generate, 0)
        grid.Add(wx.StaticText(page, label=lang.t(
            "dialogs", "password",
            "Password")), 0,
                 wx.ALIGN_CENTER_VERTICAL)
        grid.Add(password_row, 1, wx.EXPAND)

        self.url_field = add(lang.t("dialogs", "web_address", "Web address"), lambda: wx.TextCtrl(page))
        suggest = wx.Button(page, label=lang.control_label(
            "suggest_a_name_from_the_web",
            "Suggest a na&me from the web address"))
        suggest.Bind(wx.EVT_BUTTON, self.on_suggest_name)
        grid.Add(wx.StaticText(page, label=""), 0)
        grid.Add(suggest, 0)
        self.group_choice = wx.Choice(page)
        self.group_names = [lang.t("dialogs", "no_group", "(no group)")]
        for group in self.vault.groups():
            self.group_names.append(group["name"])
        self.group_choice.AppendItems(self.group_names)
        self.group_choice.SetSelection(0)
        grid.Add(wx.StaticText(page, label=lang.t("dialogs", "group", "Group")), 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.group_choice, 1, wx.EXPAND)

        self.expiry_check = wx.CheckBox(page, label=lang.control_label(
            "entry_expires_on",
            "Entry &expires on"))
        self.expiry_check.Bind(wx.EVT_CHECKBOX, self.on_expiry_toggle)
        self.expiry_picker = wx.adv.DatePickerCtrl(page)
        self.expiry_picker.Enable(False)
        grid.Add(self.expiry_check, 0)
        grid.Add(self.expiry_picker, 1, wx.EXPAND)

        self.favourite_check = wx.CheckBox(page, label=lang.control_label(
            "favourite",
            "&Favourite"))
        grid.Add(wx.StaticText(page, label=""), 0)
        grid.Add(self.favourite_check, 1)

        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t("dialogs", "general", "General"))

        self.title_field.SetValue(self.entry.get("title") or "")
        self.username_field.SetValue(self.entry.get("username") or "")
        self.password_field.SetValue(self.entry.get("password") or "")
        self.url_field.SetValue(self.entry.get("url") or "")
        if self.entry.get("group_id"):
            name = self.vault.group_name(self.entry["group_id"])
            if name in self.group_names:
                self.group_choice.SetSelection(self.group_names.index(name))
        self.favourite_check.SetValue(bool(self.entry.get("favourite")))
        if self.entry.get("expires"):
            self.expiry_check.SetValue(True)
            self.expiry_picker.Enable(True)

    def on_suggest_name(self, event):
        """Put a short name made from the web address in the Title box."""
        from . import names

        name = names.suggest({"url": self.url_field.GetValue(),
                              "title": self.title_field.GetValue()})
        if not name:
            wx.MessageBox(lang.t(
                "errors", "type_a_web_address_first_and",
                "Type a web address first, and a name can be made from it."), lang.t(
                              "dialogs", "suggest_a_name",
                              "Suggest a name"),
                          wx.OK | wx.ICON_INFORMATION, self)
            return
        self.title_field.SetValue(name)
        self.title_field.SetFocus()
        self.title_field.SelectAll()

    def on_reveal(self, event):
        style = self.password_field.GetWindowStyle()
        new_style = (style & ~wx.TE_PASSWORD) if event.IsChecked() \
            else (style | wx.TE_PASSWORD)
        self.password_field.SetWindowStyle(new_style)
        self.password_field.Refresh()

    def on_generate(self, event):
        dialog = GeneratorDialog(self, parent_settings=None)
        if dialog.ShowModal() == wx.ID_OK and dialog.result:
            self.password_field.SetValue(dialog.result)
        dialog.Destroy()

    def on_expiry_toggle(self, event):
        self.expiry_picker.Enable(event.IsChecked())

    # ------------------------------------------------------------------ notes

    def _build_notes(self):
        page = wx.Panel(self.notebook)
        self.notes_field = wx.TextCtrl(page, style=wx.TE_MULTILINE)
        self.notes_field.SetName(lang.t(
            "dialogs", "secure_notes",
            "Secure notes"))
        self.notes_field.SetValue(self.entry.get("notes") or "")
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(wx.StaticText(page, label=lang.control_label(
            "secure_notes_2",
            "Secure &notes")), 0, wx.ALL, 8)
        root.Add(self.notes_field, 1, wx.EXPAND | wx.ALL, 8)
        page.SetSizer(root)
        self.notebook.AddPage(page, lang.t("dialogs", "notes", "Notes"))

    # ------------------------------------------------------------------- TOTP

    def _build_totp(self):
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.totp_secret_field = add(lang.t(
            "dialogs", "setup_key",
            "Setup key"),
                                     lambda: wx.TextCtrl(page))
        self.totp_secret_field.SetValue(self.entry.get("totp_secret") or "")
        self.totp_secret_field.SetToolTip(
            lang.t(
                "dialogs", "paste_the_setup_key_from_the",
                "Paste the setup key from the service, or a full otpauth URL."))
        self.algorithm_choice = add(lang.t("dialogs", "algorithm", "Algorithm"), lambda: wx.Choice(
            page, choices=["SHA1", "SHA256", "SHA512"]))
        self.algorithm_choice.SetStringSelection(
            (self.entry.get("totp_algorithm") or "SHA1").upper())
        self.digits_choice = add(lang.t(
            "dialogs", "number_of_digits",
            "Number of digits"), lambda: wx.Choice(
            page, choices=["6", "8"]))
        self.digits_choice.SetStringSelection(str(self.entry.get("totp_digits") or 6))
        self.period_field = add(lang.t(
            "dialogs", "seconds_per_code",
            "Seconds per code"), lambda: wx.SpinCtrl(
            page, min=5, max=300, initial=int(self.entry.get("totp_period") or 30)))

        self.code_field = ReadOnlyField(page, style=wx.TE_READONLY)
        self.code_field.SetName(lang.t(
            "dialogs", "current_code",
            "Current code"))
        grid.Add(wx.StaticText(page, label=lang.t(
            "dialogs", "current_code",
            "Current code")), 0,
                 wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.code_field, 1, wx.EXPAND)

        self.seconds_label = wx.StaticText(page, label="")
        self.seconds_label.SetName(lang.t(
            "dialogs", "seconds_left_in_this_code",
            "Seconds left in this code"))
        grid.Add(wx.StaticText(page, label=lang.t(
            "dialogs", "valid_for",
            "Valid for")), 0,
                 wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.seconds_label, 1, wx.EXPAND)

        read_button = wx.Button(page, label=lang.control_label(
            "read_current_code",
            "&Read current code"))
        read_button.Bind(wx.EVT_BUTTON, self.on_read_code)
        copy_button = wx.Button(page, label=lang.control_label(
            "copy_current_code",
            "&Copy current code"))
        copy_button.Bind(wx.EVT_BUTTON, self.on_copy_code)
        link_button = wx.Button(page, label=lang.control_label(
            "paste_a_link_from_the_clipboard",
            "Paste a &link from the clipboard"))
        link_button.Bind(wx.EVT_BUTTON, self.on_paste_link)
        link_button.SetToolTip(
            lang.t(
                "dialogs", "copy_the_otpauth_link_a_service",
                "Copy the otpauth:// link a service shows, then press this "
                "to fill the setup key, the digits, the period and the "
                "algorithm at once."))
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(read_button, 0, wx.RIGHT, 6)
        row.Add(copy_button, 0, wx.RIGHT, 6)
        row.Add(link_button, 0)

        self.check_button = wx.Button(page, label=lang.control_label(
            "test_this_secret",
            "&Test this secret"))
        self.check_button.Bind(wx.EVT_BUTTON, self.on_test_secret)
        hint = wx.StaticText(
            page, label=lang.t(
                "dialogs", "the_code_updates_automatically_every_second",
                "The code updates automatically every second while this "
                "window is open. It is copied to the clipboard without any "
                "trailing space."))
        hint.Wrap(520)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        root.Add(row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        root.Add(self.check_button, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        root.Add(hint, 0, wx.EXPAND | wx.ALL, 12)
        page.SetSizer(root)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "authenticator",
            "Authenticator"))

        self.totp_timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, lambda event: self.update_code(), self.totp_timer)
        self.totp_timer.Start(1000)
        # Cancel and Escape close the editor too; a timer left running would
        # tick into the destroyed dialog and crash ZKeypass.
        self.Bind(wx.EVT_WINDOW_DESTROY, self.on_destroy)

    def on_destroy(self, event):
        if event.GetEventObject() is self:
            self.totp_timer.Stop()
        event.Skip()

    def update_code(self):
        entry = {
            "totp_secret": self.totp_secret_field.GetValue(),
            "totp_digits": int(self.digits_choice.GetStringSelection() or 6),
            "totp_period": self.period_field.GetValue(),
            "totp_algorithm": self.algorithm_choice.GetStringSelection() or "SHA1",
        }
        code = totp.current_code(entry)
        self.code_field.SetValue(totp.format_code(code) if code else "")
        if code:
            left = totp.seconds_remaining(int(entry["totp_period"] or 30))
            self.seconds_label.SetLabel(
                lang.t(
                    "dialogs", "seconds_then_a_new_code_appears",
                    "{left} seconds, then a new code appears",
                    left=left))
        else:
            self.seconds_label.SetLabel(lang.t(
                "dialogs", "no_valid_setup_key_yet",
                "No valid setup key yet"))

    def on_paste_link(self, event):
        """Fill the fields from an otpauth:// link on the clipboard."""
        text = ""
        if wx.TheClipboard.Open():
            data = wx.TextDataObject()
            if wx.TheClipboard.GetData(data):
                text = data.GetText()
            wx.TheClipboard.Close()
        parsed = totp.parse_otpauth(text)
        if not parsed:
            wx.MessageBox(
                lang.t(
                    "errors", "the_clipboard_does_not_hold_an",
                    "The clipboard does not hold an otpauth:// link. Copy "
                    "the setup link from the service first, or paste the "
                    "setup key into the Setup key box yourself."),
                lang.t("dialogs", "authenticator", "Authenticator"), wx.OK | wx.ICON_INFORMATION, self)
            return
        self.totp_secret_field.SetValue(parsed["secret"])
        self.algorithm_choice.SetStringSelection(
            parsed["algorithm"] if parsed["algorithm"] in ("SHA1", "SHA256",
                                                           "SHA512") else "SHA1")
        self.digits_choice.SetStringSelection(str(parsed["digits"])
                                              if str(parsed["digits"]) in
                                              ("6", "8") else "6")
        self.period_field.SetValue(int(parsed["period"] or 30))
        if parsed["account"] and not self.username_field.GetValue().strip():
            self.username_field.SetValue(parsed["account"])
        if parsed["issuer"] and not self.title_field.GetValue().strip():
            self.title_field.SetValue(parsed["issuer"])
        self.update_code()
        wx.MessageBox(
            lang.t(
                "errors", "filled_from_the_link_account_issuer",
                "Filled from the link. Account: {account}. Issuer: "
                "{issuer}. Digits: {digits}, period {period} seconds, "
                "algorithm {algorithm}.",
                account=parsed['account'] or lang.t(
                    "dialogs", "unnamed",
                    "unnamed"),
                issuer=parsed['issuer'] or lang.t(
                    "dialogs", "unnamed",
                    "unnamed"),
                digits=parsed['digits'],
                period=parsed['period'],
                algorithm=parsed['algorithm']),
            lang.t("dialogs", "authenticator", "Authenticator"), wx.OK | wx.ICON_INFORMATION, self)

    def on_read_code(self, event):
        self.update_code()
        value = self.code_field.GetValue()
        if value:
            wx.MessageBox(lang.t(
                "errors", "current_code_valid_for_more_seconds",
                "Current code: {code}. Valid for {seconds_remaining} more "
                "seconds.",
                code=value,
                seconds_remaining=totp.seconds_remaining(self.period_field.GetValue())), lang.t(
                              "dialogs", "current_code",
                              "Current code"), wx.OK, self)
        else:
            wx.MessageBox(lang.t(
                "errors", "that_secret_could_not_be_read",
                "That secret could not be read. Check the setup key."),
                          lang.t("dialogs", "current_code", "Current code"), wx.OK | wx.ICON_WARNING, self)

    def on_copy_code(self, event):
        self.update_code()
        value = self.code_field.GetValue().replace(" ", "")
        if value:
            _copy_secret(self, value, lang.t(
                "actions_announcements", "code",
                "Code {code}",
                code=self.code_field.GetValue()))

    def on_test_secret(self, event):
        self.update_code()
        if self.code_field.GetValue():
            wx.MessageBox(lang.t(
                "errors", "the_secret_works_a_code_was",
                "The secret works. A code was generated successfully."),
                          lang.t("dialogs", "authenticator", "Authenticator"), wx.OK | wx.ICON_INFORMATION, self)
        else:
            wx.MessageBox(lang.t(
                "errors", "no_code_could_be_generated_from",
                "No code could be generated from that secret."),
                          lang.t("dialogs", "authenticator", "Authenticator"), wx.OK | wx.ICON_WARNING, self)

    # ------------------------------------------------------------- attributes

    def _build_attributes(self):
        page = wx.Panel(self.notebook)
        self.attribute_list = wx.ListCtrl(page,
                                          style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.attribute_list.SetName(lang.t(
            "dialogs", "extra_fields",
            "Extra fields"))
        self.attribute_list.InsertColumn(0, lang.t("dialogs", "name", "Name"), width=180)
        self.attribute_list.InsertColumn(1, lang.t("dialogs", "value", "Value"), width=260)
        self.attribute_list.InsertColumn(2, lang.t(
            "dialogs", "hidden",
            "Hidden"), width=80)
        self.refresh_attributes()

        name_field = wx.TextCtrl(page)
        name_field.SetName(lang.t("dialogs", "field_name", "Field name"))
        value_field = wx.TextCtrl(page)
        value_field.SetName(lang.t("dialogs", "field_value", "Field value"))
        hidden_check = wx.CheckBox(page, label=lang.control_label(
            "hidden_2",
            "&Hidden"))
        self.attribute_name = name_field
        self.attribute_value = value_field
        self.attribute_hidden = hidden_check

        add_button = wx.Button(page, label=lang.control_label(
            "add_field",
            "&Add field"))
        update_button = wx.Button(page, label=lang.control_label(
            "update_selected",
            "&Update selected"))
        remove_button = wx.Button(page, label=lang.control_label(
            "remove_selected",
            "&Remove selected"))
        add_button.Bind(wx.EVT_BUTTON, self.on_add_attribute)
        update_button.Bind(wx.EVT_BUTTON, self.on_update_attribute)
        remove_button.Bind(wx.EVT_BUTTON, self.on_remove_attribute)
        self.attribute_list.Bind(wx.EVT_LIST_ITEM_SELECTED,
                                 self.on_attribute_selected)

        grid, add = labelled(page)
        add(lang.t("dialogs", "field_name", "Field name"), name_field)
        add(lang.t("dialogs", "field_value", "Field value"), value_field)
        grid.Add(wx.StaticText(page, label=""), 0)
        grid.Add(hidden_check, 1)

        buttons = wx.BoxSizer(wx.HORIZONTAL)
        for button in (add_button, update_button, remove_button):
            buttons.Add(button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.attribute_list, 1, wx.EXPAND | wx.ALL, 8)
        root.Add(grid, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 8)
        root.Add(buttons, 0, wx.ALL, 8)
        page.SetSizer(root)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "extra_fields",
            "Extra fields"))

    def refresh_attributes(self):
        self.attribute_list.DeleteAllItems()
        for row, attribute in enumerate(self.attributes):
            self.attribute_list.InsertItem(row, attribute["name"])
            self.attribute_list.SetItem(row, 1, "" if attribute["hidden"]
                                        else attribute["value"])
            self.attribute_list.SetItem(
                row, 2, lang.t("dialogs", "yes_word", "yes")
                if attribute["hidden"] else "")

    def on_attribute_selected(self, event):
        row = event.GetIndex()
        if 0 <= row < len(self.attributes):
            attribute = self.attributes[row]
            self.attribute_name.SetValue(attribute["name"])
            self.attribute_value.SetValue(attribute["value"])
            self.attribute_hidden.SetValue(bool(attribute["hidden"]))

    def on_add_attribute(self, event):
        name = self.attribute_name.GetValue().strip()
        if not name:
            return
        self.attributes.append({"id": None, "name": name,
                                "value": self.attribute_value.GetValue(),
                                "hidden": self.attribute_hidden.GetValue()})
        self.attribute_name.SetValue("")
        self.attribute_value.SetValue("")
        self.attribute_hidden.SetValue(False)
        self.refresh_attributes()

    def on_update_attribute(self, event):
        row = self.attribute_list.GetFirstSelected()
        if row < 0:
            return
        self.attributes[row] = {
            "id": self.attributes[row].get("id"),
            "name": self.attribute_name.GetValue().strip() or
                    self.attributes[row]["name"],
            "value": self.attribute_value.GetValue(),
            "hidden": self.attribute_hidden.GetValue(),
        }
        self.refresh_attributes()

    def on_remove_attribute(self, event):
        row = self.attribute_list.GetFirstSelected()
        if row >= 0:
            del self.attributes[row]
            self.refresh_attributes()

    # -------------------------------------------------------------- auto-type

    def _build_autotype(self):
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        existing = {}
        for attribute in self.attributes:
            if attribute["name"] in (autotype_store.ATTR_ENABLED,
                                     autotype_store.ATTR_SEQUENCE):
                existing[attribute["name"]] = attribute["value"]

        self.autotype_enabled = wx.CheckBox(
            page, label=lang.control_label(
                "allow_auto_type_for_this_entry",
                "Allow &auto-type for this entry"))
        self.autotype_enabled.SetValue(
            (existing.get(autotype_store.ATTR_ENABLED, "1") or "1")
            not in ("", "0", "false", "False"))
        self.autotype_sequence = wx.TextCtrl(
            page, value=existing.get(autotype_store.ATTR_SEQUENCE, ""))
        self.autotype_sequence.SetName(lang.t(
            "dialogs", "sequence",
            "Sequence"))
        self.autotype_preset = wx.Choice(
            page, choices=[lang.sequence_name(name)
                           for name, _value in _SEQUENCE_PRESETS])
        self.autotype_preset.SetName(lang.t(
            "dialogs", "common_sequences",
            "Common sequences"))
        self.autotype_preset.Bind(wx.EVT_CHOICE, self.on_autotype_preset)
        self.autotype_windows = wx.TextCtrl(
            page, style=wx.TE_MULTILINE,
            value="\n".join(line for line in
                            (existing.get(autotype_store.ATTR_ASSOCIATION, "")
                             or "").splitlines() if line.strip()))
        self.autotype_windows.SetName(lang.t(
            "dialogs", "window_patterns_one_per_line",
            "Window patterns, one per line"))

        read_button = wx.Button(page, label=lang.control_label(
            "read_active_window_title",
            "Read a&ctive window title"))
        read_button.Bind(wx.EVT_BUTTON, self.on_read_window)
        preview_button = wx.Button(page, label=lang.control_label(
            "show_what_would_be_typed",
            "&Show what would be typed"))
        preview_button.Bind(wx.EVT_BUTTON, self.on_autotype_preview)
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(read_button, 0, wx.RIGHT, 6)
        row.Add(preview_button, 0)

        hint = wx.StaticText(
            page, label=lang.t(
                "dialogs", "leave_the_sequence_blank_to_use",
                "Leave the sequence blank to use the standard one. Window "
                "patterns accept * and ? wildcards and match any part of the "
                "window title; separate alternatives with |."))
        hint.Wrap(520)

        add(lang.t("dialogs", "sequence", "Sequence"), self.autotype_sequence)
        add(lang.t("dialogs", "common_sequences", "Common sequences"), self.autotype_preset)
        grid.Add(wx.StaticText(page, label=""), 0)
        grid.Add(self.autotype_enabled, 1)
        add(lang.t(
            "dialogs", "window_patterns_one_per_line",
            "Window patterns, one per line"), self.autotype_windows)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        root.Add(row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        root.Add(hint, 0, wx.EXPAND | wx.ALL, 12)
        page.SetSizer(root)
        self.notebook.AddPage(page, "Auto-type")

    def on_autotype_preset(self, event):
        index = self.autotype_preset.GetSelection()
        if 0 <= index < len(_SEQUENCE_PRESETS):
            self.autotype_sequence.SetValue(_SEQUENCE_PRESETS[index][1])

    def on_read_window(self, event):
        from . import autotype

        title = autotype.active_window_title()
        current = self.autotype_windows.GetValue().strip()
        line = f"*{title}*" if title else ""
        if not line:
            wx.MessageBox(lang.t(
                "errors", "no_window_with_a_title_has",
                "No window with a title has the focus."),
                          "Auto-type", wx.OK | wx.ICON_INFORMATION, self)
            return
        self.autotype_windows.SetValue(f"{current}\n{line}".strip())

    def on_autotype_preview(self, event):
        from . import autotype

        record = {
            "title": self.title_field.GetValue(), "username":
            self.username_field.GetValue(), "password": self.password_field.GetValue(),
            "url": self.url_field.GetValue(), "notes": self.notes_field.GetValue(),
        }
        code = ""
        if self.totp_secret_field.GetValue().strip():
            code = totp.format_code(totp.current_code({
                "totp_secret": self.totp_secret_field.GetValue(),
                "totp_digits": int(self.digits_choice.GetStringSelection() or 6),
                "totp_period": self.period_field.GetValue(),
                "totp_algorithm": self.algorithm_choice.GetStringSelection(),
            }))
        sequence = self.autotype_sequence.GetValue().strip()
        complaint = autotype.validate_sequence(sequence)
        if complaint:
            wx.MessageBox(complaint, "Auto-type", wx.OK | wx.ICON_WARNING, self)
            return
        wx.MessageBox(lang.t(
            "dialogs", "zkeypass_would_type",
            "ZKeypass would type:\n\n") +
                      autotype.expand(sequence, record, "", code),
                      lang.t(
                          "dialogs", "auto_type_preview",
                          "Auto-type preview"), wx.OK | wx.ICON_INFORMATION, self)

    # --------------------------------------------------------------- passkeys

    def _build_passkeys(self):
        page = wx.Panel(self.notebook)
        self.passkey_list = wx.ListCtrl(page, style=wx.LC_REPORT |
                                                     wx.LC_SINGLE_SEL)
        self.passkey_list.SetName(lang.t(
            "dialogs", "passkeys_stored_on_this_entry",
            "Passkeys stored on this entry"))
        self.passkey_list.InsertColumn(0, lang.t(
            "dialogs", "website",
            "Website"), width=220)
        self.passkey_list.InsertColumn(1, lang.t(
            "dialogs", "user_name",
            "User name"), width=160)
        self.passkey_list.InsertColumn(2, lang.t(
            "dialogs", "algorithm",
            "Algorithm"), width=180)
        for attribute in self.attributes:
            if attribute["name"] == passkeylib.ATTR_RELYING_PARTY:
                row = self.passkey_list.GetItemCount()
                self.passkey_list.InsertItem(row, attribute["value"])
        self.passkey_algorithm = wx.Choice(
            page, choices=list(passkeylib.ALGORITHM_IDS))
        self.passkey_algorithm.SetName(lang.t(
            "dialogs", "algorithm_for_a_new_passkey",
            "Algorithm for a new passkey"))
        self.passkey_algorithm.SetStringSelection("ES256")
        create_button = wx.Button(page, label=lang.control_label(
            "create_a_passkey_in_this_entry",
            "&Create a passkey in this entry"))
        create_button.Bind(wx.EVT_BUTTON, self.on_create_passkey)
        manage_button = wx.Button(page, label=lang.control_label(
            "manage_passkeys",
            "&Manage passkeys..."))
        manage_button.Bind(wx.EVT_BUTTON, self.on_manage_passkeys)

        grid, add = labelled(page)
        add(lang.t(
            "dialogs", "algorithm_for_a_new_passkey",
            "Algorithm for a new passkey"), self.passkey_algorithm)

        hint = wx.StaticText(
            page, label=lang.t(
                "dialogs", "a_passkey_created_here_is_saved",
                "A passkey created here is saved when you choose OK. "
                "Managing passkeys on an entry that has never been saved "
                "works only after the first save."))
        hint.Wrap(520)
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(create_button, 0, wx.RIGHT, 6)
        row.Add(manage_button, 0)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.passkey_list, 1, wx.EXPAND | wx.ALL, 12)
        root.Add(grid, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 12)
        root.Add(row, 0, wx.ALL, 12)
        root.Add(hint, 0, wx.EXPAND | wx.ALL, 12)
        page.SetSizer(root)
        self.notebook.AddPage(page, lang.t("dialogs", "passkeys", "Passkeys"))
        self.pending_passkeys = []

    def on_create_passkey(self, event):
        relying_party = ""
        url = self.url_field.GetValue().strip()
        if url:
            from .browser import _host_of

            relying_party = _host_of(url)
        if not relying_party:
            relying_party = wx.GetTextFromUser(
                lang.t(
                    "dialogs", "the_website_the_passkey_is_for",
                    "The website the passkey is for:"), lang.t(
                    "dialogs", "new_passkey",
                    "New passkey"),
                "", self)
        if not relying_party:
            return
        try:
            record = passkeylib.new_passkey(
                relying_party, self.username_field.GetValue().strip(),
                algorithm=self.passkey_algorithm.GetStringSelection() or "ES256")
        except passkeylib.PasskeyError as error:
            wx.MessageBox(str(error), lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_ERROR, self)
            return
        self.pending_passkeys.append(record)
        row = self.passkey_list.GetItemCount()
        self.passkey_list.InsertItem(row, record["relying_party"])
        self.passkey_list.SetItem(row, 1, record["username"])
        self.passkey_list.SetItem(row, 2, passkeylib.ALGORITHM_NAMES.get(
            record["algorithm"], ""))
        wx.MessageBox(lang.t(
            "errors", "the_passkey_will_be_stored_when",
            "The passkey will be stored when you choose OK."),
                      lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_INFORMATION, self)

    def on_manage_passkeys(self, event):
        if not self.entry_id:
            wx.MessageBox(lang.t(
                "errors", "save_the_entry_once_then_manage",
                "Save the entry once, then manage its passkeys."),
                          lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_INFORMATION, self)
            return
        from .dialogs_extras import PasskeysDialog

        dialog = PasskeysDialog(self, self.vault, self.entry_id)
        dialog.ShowModal()
        dialog.Destroy()

    # ------------------------------------------------------------ attachments

    def _build_attachments(self):
        page = wx.Panel(self.notebook)
        page.SetDropTarget(AttachmentDropTarget(self, page))
        self.attachment_list = wx.ListCtrl(page,
                                           style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.attachment_list.SetName(lang.t(
            "dialogs", "stored_files",
            "Stored files"))
        self.attachment_list.InsertColumn(0, lang.t(
            "dialogs", "file_name",
            "File name"), width=280)
        self.attachment_list.InsertColumn(1, lang.t(
            "dialogs", "size_in_bytes",
            "Size in bytes"), width=120)
        self.refresh_attachments()

        add_button = wx.Button(page, label=lang.control_label(
            "add_file",
            "&Add file..."))
        save_button = wx.Button(page, label=lang.control_label(
            "save_as_2",
            "&Save as..."))
        remove_button = wx.Button(page, label=lang.control_label(
            "remove",
            "&Remove"))
        add_button.Bind(wx.EVT_BUTTON, self.on_add_attachment)
        save_button.Bind(wx.EVT_BUTTON, self.on_save_attachment)
        remove_button.Bind(wx.EVT_BUTTON, self.on_remove_attachment)

        buttons = wx.BoxSizer(wx.HORIZONTAL)
        for button in (add_button, save_button, remove_button):
            buttons.Add(button, 0, wx.RIGHT, 6)

        hint = wx.StaticText(
            page, label=lang.t(
                "dialogs", "files_are_encrypted_inside_the_database",
                "Files are encrypted inside the database. Dropping files "
                "onto the main window also stores them in the selected entry."))
        hint.Wrap(520)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.attachment_list, 1, wx.EXPAND | wx.ALL, 8)
        root.Add(buttons, 0, wx.ALL, 8)
        root.Add(hint, 0, wx.EXPAND | wx.ALL, 8)
        page.SetSizer(root)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "stored_files",
            "Stored files"))

    def refresh_attachments(self):
        self.attachment_list.DeleteAllItems()
        for row, attachment in enumerate(self.attachments):
            self.attachment_list.InsertItem(row, attachment["name"])
            self.attachment_list.SetItem(row, 1, str(attachment.get("size", 0)))

    def add_attachment_path(self, path):
        """Add one file to the list of stored files waiting to be saved."""
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_read",
                "Could not read {path}: {error}",
                path=path,
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        existing = [attachment["name"] for attachment in self.attachments]
        name = os.path.basename(path)
        if name in existing:
            name = f"{os.path.splitext(name)[0]} (2){os.path.splitext(name)[1]}"
        self.attachments.append({"id": None, "name": name, "size": len(data),
                                 "data": data})

    def on_add_attachment(self, event):
        path, _kind = filebrowser.choose_file(
            self, title=lang.t(
                "dialogs", "choose_a_file_to_encrypt",
                "Choose a file to encrypt"),
            wildcard=filebrowser.ANY_WILDCARD)
        if path:
            self.add_attachment_path(path)
            self.refresh_attachments()

    def on_save_attachment(self, event):
        row = self.attachment_list.GetFirstSelected()
        if row < 0:
            return
        attachment = self.attachments[row]
        os.makedirs(paths.EXPORT_DIR, exist_ok=True)
        target, _kind = filebrowser.choose_file(
            self, title=lang.t(
                "dialogs", "save_stored_file",
                "Save stored file"), default_dir=paths.EXPORT_DIR,
            default_name=attachment["name"],
            wildcard=filebrowser.ANY_WILDCARD, save=True)
        if not target:
            return
        if attachment.get("id"):
            data = self.vault.attachment_data(attachment["id"])
        else:
            data = attachment.get("data", b"")
        try:
            with open(target, "wb") as handle:
                handle.write(data or b"")
        except OSError as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_save_the_stored_file",
                "Could not save the stored file: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)

    def on_remove_attachment(self, event):
        row = self.attachment_list.GetFirstSelected()
        if row >= 0:
            attachment = self.attachments.pop(row)
            if attachment.get("id"):
                self.removed_attachments.append(attachment["id"])
            self.refresh_attachments()

    def save_autotype(self, entry_id):
        """Store the auto-type page. Only writes when something was filled in."""
        sequence = self.autotype_sequence.GetValue().strip()
        windows = self.autotype_windows.GetValue()
        pairs = []
        for line in windows.splitlines():
            if "|" in line:
                window, assoc_sequence = line.split("|", 1)
            else:
                window, assoc_sequence = line, ""
            if window.strip():
                pairs.append([window.strip(), assoc_sequence])
        try:
            autotype_store.set_enabled(self.vault, entry_id,
                                       self.autotype_enabled.GetValue())
            if sequence or pairs:
                autotype_store.set_sequence(self.vault, entry_id, sequence)
                autotype_store.set_associations(self.vault, entry_id, pairs)
        except Exception:
            pass

    # ------------------------------------------------------------------- save

    def on_ok(self, event):
        if not self.title_field.GetValue().strip():
            wx.MessageBox(lang.t(
                "errors", "give_the_entry_a_title",
                "Give the entry a title."), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        secret = self.totp_secret_field.GetValue().strip()
        if secret and not totp.is_valid_secret(secret):
            if not ask_yes_no(self, lang.t(
                "dialogs", "that_setup_key_does_not_look",
                "That setup key does not look valid. Save it anyway?")):
                return
        entry = {
            "id": self.entry_id,
            "title": self.title_field.GetValue().strip(),
            "username": self.username_field.GetValue(),
            "password": self.password_field.GetValue(),
            "url": self.url_field.GetValue(),
            "notes": self.notes_field.GetValue(),
            "totp_secret": totp.normalise_secret(secret),
            "totp_digits": int(self.digits_choice.GetStringSelection() or 6),
            "totp_period": self.period_field.GetValue(),
            "totp_algorithm": self.algorithm_choice.GetStringSelection() or "SHA1",
            "expires": 0,
            "favourite": self.favourite_check.GetValue(),
            "group_id": None,
        }
        if self.expiry_check.GetValue():
            date = self.expiry_picker.GetValue()
            entry["expires"] = time.mktime(
                datetime.date(date.GetYear(), date.GetMonth() + 1,
                              date.GetDay()).timetuple())
        group_selection = self.group_choice.GetSelection()
        if group_selection > 0:
            groups = self.vault.groups()
            if group_selection - 1 < len(groups):
                entry["group_id"] = groups[group_selection - 1]["id"]

        entry_id = self.vault.save_entry(entry)

        for attribute in self.attributes:
            if attribute.get("id"):
                self.vault.update_attribute(attribute["id"], attribute["name"],
                                            attribute["value"],
                                            attribute["hidden"])
            else:
                self.vault.add_attribute(entry_id, attribute["name"],
                                         attribute["value"], attribute["hidden"])
        for attachment_id in self.removed_attachments:
            self.vault.delete_attachment(attachment_id)
        for attachment in self.attachments:
            if not attachment.get("id") and attachment.get("data") is not None:
                self.vault.add_attachment(entry_id, attachment["name"],
                                          attachment["data"])
        self.save_autotype(entry_id)
        for record in getattr(self, "pending_passkeys", []):
            passkeylib.store_passkey(self.vault, entry_id, record)
        self.totp_timer.Stop()
        self.EndModal(wx.ID_OK)


class GeneratorDialog(wx.Dialog):
    """Character passwords or Diceware passphrases, with live strength readout."""

    def __init__(self, parent, parent_settings=None):
        super().__init__(parent, title=lang.t(
            "dialogs", "password_generator",
            "Password generator"), size=(620, 520))
        self.settings = parent_settings
        self.result = ""
        self.wordlist = []

        self.notebook = wx.Notebook(self)
        self.notebook.SetName(lang.t(
            "dialogs", "generator_type",
            "Generator type"))
        self._build_password_page()
        self._build_passphrase_page()

        self.output = ReadOnlyField(self, style=wx.TE_READONLY)
        self.output.SetName(lang.t(
            "dialogs", "generated_value",
            "Generated value"))
        self.strength = wx.StaticText(self, label="")
        copy_button = wx.Button(self, label=lang.control_label("copy", "&Copy"))
        use_button = wx.Button(self, label=lang.control_label(
            "use_this_value",
            "&Use this value"))
        new_button = wx.Button(self, label=lang.control_label(
            "generate_another",
            "Generate a&nother"))
        copy_button.Bind(wx.EVT_BUTTON, self.on_copy)
        use_button.Bind(wx.EVT_BUTTON, self.on_use)
        new_button.Bind(wx.EVT_BUTTON, self.on_generate)

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (new_button, copy_button, use_button):
            row.Add(button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.notebook, 1, wx.EXPAND | wx.ALL, 8)
        root.Add(self.output, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 8)
        root.Add(self.strength, 0, wx.ALL, 8)
        root.Add(row, 0, wx.ALL, 8)
        self.SetSizer(root)
        self.on_generate(None)

    def _build_password_page(self):
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.length_slider = wx.Slider(page, minValue=4, maxValue=128, value=20,
                                       style=wx.SL_HORIZONTAL | wx.SL_LABELS)
        self.length_slider.SetName(lang.t(
            "dialogs", "password_length",
            "Password length"))
        grid.Add(wx.StaticText(page, label=lang.t(
            "dialogs", "length",
            "Length")), 0,
                 wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.length_slider, 1, wx.EXPAND)
        self.upper_check = add(lang.t(
            "dialogs", "uppercase_letters_a_to_z",
            "Uppercase letters A to Z"), lambda: wx.CheckBox(page))
        self.lower_check = add(lang.t(
            "dialogs", "lowercase_letters_a_to_z",
            "Lowercase letters a to z"), lambda: wx.CheckBox(page))
        self.digits_check = add(lang.t(
            "dialogs", "digits_0_to_9",
            "Digits 0 to 9"), lambda: wx.CheckBox(page))
        self.symbols_check = add(lang.t("dialogs", "symbols", "Symbols"), lambda: wx.CheckBox(page))
        self.extended_check = add(lang.t(
            "dialogs", "extra_symbols",
            "Extra symbols"), lambda: wx.CheckBox(page))
        self.ambiguous_check = add(lang.t(
            "dialogs", "avoid_look_alike_characters",
            "Avoid look-alike characters"), lambda: wx.CheckBox(page))
        for check in (self.upper_check, self.lower_check, self.digits_check,
                      self.symbols_check):
            check.SetValue(True)
        for check in (self.length_slider, self.upper_check, self.lower_check,
                      self.digits_check, self.symbols_check, self.extended_check,
                      self.ambiguous_check):
            check.Bind(wx.EVT_CHECKBOX, self.on_generate)
            check.Bind(wx.EVT_SLIDER, self.on_generate)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "random_password",
            "Random password"))

    def _build_passphrase_page(self):
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.words_spinner = add(lang.t(
            "dialogs", "number_of_words",
            "Number of words"), lambda: wx.SpinCtrl(
            page, min=2, max=20, initial=5))
        self.separator_field = add(lang.t("dialogs", "separator", "Separator"), lambda: wx.TextCtrl(page, value="-"))
        self.capitalise_check = add(lang.t(
            "dialogs", "capitalise_each_word",
            "Capitalise each word"), lambda: wx.CheckBox(page))
        self.number_check = add(lang.t(
            "dialogs", "add_a_four_digit_number",
            "Add a four digit number"), lambda: wx.CheckBox(page))
        self.capitalise_check.SetValue(True)
        self.number_check.SetValue(True)
        for control in (self.words_spinner, self.separator_field,
                        self.capitalise_check, self.number_check):
            control.Bind(wx.EVT_SPINCTRL, self.on_generate)
            control.Bind(wx.EVT_TEXT, self.on_generate)
            control.Bind(wx.EVT_CHECKBOX, self.on_generate)
        self.wordlist_status = wx.StaticText(page, label="")
        self.wordlist_status.Wrap(520)

        from .generator import load_wordlist
        self.wordlist = load_wordlist()
        if self.wordlist:
            self.wordlist_status.SetLabel(
                lang.t(
                    "dialogs", "wordlist_loaded_words_from_the_wordlists",
                    "Wordlist loaded: {count} words from the wordlists "
                    "folder.",
                    count=len(self.wordlist)))
        else:
            self.wordlist_status.SetLabel(
                lang.t(
                    "dialogs", "no_wordlist_found_put_a_diceware",
                    "No wordlist found. Put a Diceware or EFF long wordlist "
                    "as a text file in {wordlist_dir} to enable passphrases.",
                    wordlist_dir=paths.WORDLIST_DIR))

        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(self.wordlist_status, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "passphrase",
            "Passphrase"))

    def on_generate(self, event=None):
        from .generator import (build_alphabet, entropy_bits, generate_passphrase,
                                generate_password, passphrase_entropy)
        try:
            if self.notebook.GetSelection() == 0:
                options = {
                    "use_upper": self.upper_check.GetValue(),
                    "use_lower": self.lower_check.GetValue(),
                    "use_digits": self.digits_check.GetValue(),
                    "use_symbols": self.symbols_check.GetValue(),
                    "use_extended": self.extended_check.GetValue(),
                    "avoid_ambiguous": self.ambiguous_check.GetValue(),
                }
                alphabet = build_alphabet(**options)
                value = generate_password(self.length_slider.GetValue(), alphabet)
                bits = entropy_bits(len(alphabet), len(value))
            else:
                value, size = generate_passphrase(
                    self.words_spinner.GetValue(),
                    self.separator_field.GetValue() or "-",
                    self.capitalise_check.GetValue(),
                    self.number_check.GetValue(),
                    self.wordlist,
                )
                bits = passphrase_entropy(self.words_spinner.GetValue(), size)
                if self.number_check.GetValue():
                    bits += 13
        except ValueError as error:
            self.output.SetValue("")
            self.strength.SetLabel(str(error))
            return
        self.result = value
        self.output.SetValue(value)
        self.strength.SetLabel(
            lang.t(
                "dialogs", "strength_about_bits",
                "Strength: {strength_label}, about {bits:.0f} bits.",
                strength_label=health.strength_label(bits),
                bits=bits))

    def on_copy(self, event):
        if self.result:
            _copy_secret(self, self.result, lang.t(
                "actions_announcements", "password",
                "Password"))

    def on_use(self, event):
        if self.result:
            self.EndModal(wx.ID_OK)


class SettingsDialog(wx.Dialog):
    """Preferences. Nothing secret is stored here."""

    FIELDS = (
        ("clipboard_clear_seconds", "Clear the clipboard after this many seconds",
         0, 600, "Zero keeps the clipboard until you clear it yourself."),
        ("auto_lock_minutes", "Lock the database after this many minutes idle",
         0, 480, "Zero disables automatic locking."),
        ("max_age_days", "Report passwords older than this many days",
         0, 3650, "Zero disables the age check."),
        ("weak_bits", "Treat passwords under this many bits as weak",
         20, 120, "Sixty bits is a reasonable target for new passwords."),
    )

    def __init__(self, parent, settings):
        super().__init__(parent, title=lang.t(
            "dialogs", "settings",
            "Settings"), size=(660, 620))
        self.settings = settings
        self.spinners = {}
        self.notebook = wx.Notebook(self)
        self.notebook.SetName(lang.t(
            "dialogs", "settings_sections",
            "Settings sections"))

        # --- General -------------------------------------------------------
        general = wx.Panel(self.notebook)
        grid, add = labelled(general)
        self.language_codes = [""] + [
            code for code, _name in lang.available(paths.LANG_DIR)]
        language_names = [lang.t("dialogs", "language_same_as_windows",
                                 "Same as Windows")] + [
            name for _code, name in lang.available(paths.LANG_DIR)]
        self.language_choice = add(
            lang.t("dialogs", "language_label", "Language"),
            lambda: wx.Choice(general, choices=language_names))
        current_language = settings.get("language") or ""
        self.language_choice.SetSelection(
            self.language_codes.index(current_language)
            if current_language in self.language_codes else 0)
        grid.Add(wx.StaticText(general, label=""), 0)
        language_hint = wx.StaticText(general, label=lang.t(
            "dialogs", "language_note",
            "Takes effect the next time ZKeypass starts. Language files are "
            "plain text files in the lang folder inside apps_files."))
        language_hint.Wrap(520)
        grid.Add(language_hint, 1, wx.EXPAND)
        for key, caption, low, high, note in self.FIELDS:
            caption = lang.t("dialogs", "setting_" + key, caption)
            note = lang.t("dialogs", "setting_" + key + "_note", note)
            spinner = add(caption, lambda: wx.SpinCtrl(
                general, min=low, max=high, initial=int(settings.get(key) or 0)))
            self.spinners[key] = spinner
            grid.Add(wx.StaticText(general, label=""), 0)
            hint = wx.StaticText(general, label=note)
            hint.Wrap(520)
            grid.Add(hint, 1, wx.EXPAND)
        from . import speech

        self.announce_modes = ("auto", "always", "never")
        self.announce_choice = add(lang.t(
            "dialogs", "announce_actions_aloud",
            "Announce actions aloud"), lambda: wx.Choice(
            general, choices=[lang.t(
                "dialogs", "automatically_while_a_screen_reader_is",
                "Automatically, while a screen reader is running"),
                              lang.t("dialogs", "always", "Always"), lang.t("dialogs", "never", "Never")]))
        current = settings.get("announce_actions") or "auto"
        self.announce_choice.SetSelection(
            self.announce_modes.index(current) if current in self.announce_modes
            else 0)
        grid.Add(wx.StaticText(general, label=""), 0)
        detected = wx.StaticText(
            general, label=speech.describe_detection() + lang.t(
                "dialogs", "announcements_such_as_password_copied_are",
                " Announcements such as \"Password copied\" are spoken "
                "through it; the status bar always shows them."))
        detected.Wrap(520)
        grid.Add(detected, 1, wx.EXPAND)
        self.online_names_check = wx.CheckBox(
            general, label=lang.control_label(
                "look_up_page_names_online_without",
                "Look up page &names online without asking each time"))
        self.online_names_check.SetValue(bool(settings.get("names_online_allowed")))
        online_hint = wx.StaticText(
            general, label=lang.t(
                "dialogs", "zkeypass_never_goes_online_by_itself",
                "ZKeypass never goes online by itself. Suggest names can read "
                "each site's page title, only when you press its Look up "
                "button. With this off, it asks you first every time."))
        online_hint.Wrap(520)
        general.SetSizer(wx.BoxSizer(wx.VERTICAL))
        general.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        general.GetSizer().Add(self.online_names_check, 0, wx.LEFT | wx.RIGHT, 12)
        general.GetSizer().Add(online_hint, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(general, lang.t("dialogs", "general", "General"))

        # --- Auto-type ----------------------------------------------------
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.autotype_check = add(
            lang.t(
                "dialogs", "global_auto_type_hot_key",
                "Global auto-type hot key"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "turn_the_hot_key_on",
                "Turn the &hot key on")))
        self.autotype_check.SetValue(bool(settings.get("autotype_enabled")))
        self.hotkey_field = add(lang.t("dialogs", "hot_key", "Hot key"), lambda: wx.TextCtrl(
            page, value=settings.get("autotype_hotkey") or "Ctrl+Alt+A"))
        self.delay_spinner = add(lang.t(
            "dialogs", "delay_between_keystrokes_milliseconds",
            "Delay between keystrokes, milliseconds"),
                                 lambda: wx.SpinCtrl(page, min=0, max=500,
                                             initial=int(settings.get(
                                                 "autotype_delay_ms") or 20)))
        self.minimise_check = add(
            lang.t(
                "dialogs", "hide_zkeypass_while_typing",
                "Hide ZKeypass while typing"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "minimise_zkeypass_before_typing",
                "&Minimise ZKeypass before typing")))
        self.minimise_check.SetValue(bool(settings.get("autotype_minimise")))
        note = wx.StaticText(
            page, label=lang.t(
                "dialogs", "the_hot_key_works_from_any",
                "The hot key works from any program. Press it, pick the "
                "entry, and ZKeypass types into whichever window has the "
                "focus. A delay of twenty milliseconds suits most programs; "
                "raise it for slow remote sessions."))
        note.Wrap(520)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(note, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, "Auto-type")

        # --- Browser ------------------------------------------------------
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.browser_check = add(
            lang.t("dialogs", "browser_integration", "Browser integration"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "listen_for_a_browser_extension",
                "&Listen for a browser extension")))
        self.browser_check.SetValue(bool(settings.get("browser_enabled")))
        self.browser_port = add(lang.t("dialogs", "port", "Port"), lambda: wx.SpinCtrl(
            page, min=1024, max=65535,
            initial=int(settings.get("browser_port") or 19455)))
        self.browser_ask = add(
            lang.t("dialogs", "ask_before_pairing", "Ask before pairing"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "ask_me_before_a_browser_is",
                "Ask me before a browser is &paired")))
        self.browser_ask.SetValue(bool(settings.get("browser_ask", True)))
        note = wx.StaticText(
            page, label=lang.t(
                "dialogs", "the_service_listens_on_this_machine",
                "The service listens on this machine only, at 127.0.0.1. "
                "Messages after the handshake are sealed with "
                "ChaCha20-Poly1305. Paired browsers are recorded inside the "
                "database, so pairing travels with it."))
        note.Wrap(520)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(note, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t("dialogs", "browser", "Browser"))

        # --- Two-factor authenticator --------------------------------------
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.totp_hotkey_check = add(
            lang.t(
                "dialogs", "global_copy_a_code_hot_key",
                "Global copy-a-code hot key"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "turn_the_hot_key_on",
                "Turn the &hot key on")))
        self.totp_hotkey_check.SetValue(
            bool(settings.get("totp_hotkey_enabled", True)))
        self.totp_hotkey_field = add(lang.t("dialogs", "hot_key", "Hot key"), lambda: wx.TextCtrl(
            page, value=settings.get("totp_hotkey") or "Ctrl+Alt+T"))
        self.totp_announce_check = add(
            lang.t("dialogs", "announce_a_new_code", "Announce a new code"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "speak_the_new_code_when_it",
                "&Speak the new code when it rotates")))
        self.totp_announce_check.SetValue(
            bool(settings.get("totp_announce_rotation", True)))
        self.totp_seconds_check = add(
            lang.t("dialogs", "show_the_seconds_left", "Show the seconds left"),
            lambda: wx.CheckBox(page, label=lang.control_label(
                "show_a_seconds_valid_column",
                "Show a &seconds-valid column")))
        self.totp_seconds_check.SetValue(
            bool(settings.get("totp_show_seconds", True)))
        note = wx.StaticText(
            page, label=lang.t(
                "dialogs", "the_hot_key_always_copies_the",
                "The hot key always copies the code of the account selected "
                "on the Authenticator page, so you can paste it into any "
                "program without leaving ZKeypass. The key must end with a "
                "letter, for example Control+Alt+T."))
        note.Wrap(520)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(note, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "authenticator",
            "Authenticator"))

        # --- Security key -------------------------------------------------
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.slot_choice = add(lang.t(
            "dialogs", "security_key_slot",
            "Security key slot"), lambda: wx.Choice(
            page, choices=[lang.t(
                "dialogs", "slot_1_long_press",
                "Slot 1, long press"), lang.t(
                "dialogs", "slot_2_short_press",
                "Slot 2, short press")]))
        self.slot_choice.SetSelection(int(settings.get("yubikey_slot") or 1) - 1)
        self.key_algorithm = add(lang.t(
            "dialogs", "passkey_algorithm",
            "Passkey algorithm"), lambda: wx.Choice(
            page, choices=["ES256", "EdDSA", "RS256"]))
        self.key_algorithm.SetStringSelection(
            settings.get("passkey_algorithm") or "ES256")
        test_button = wx.Button(page, label=lang.control_label(
            "test_the_security_key_now",
            "&Test the security key now"))
        test_button.Bind(wx.EVT_BUTTON, self.on_test_key)
        note = wx.StaticText(
            page, label=lang.t(
                "dialogs", "a_security_key_can_be_required",
                "A security key can be required when a database is opened or "
                "created. ZKeypass sends the challenge itself over USB; the "
                "answer is never written to disk."))
        note.Wrap(520)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(test_button, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        page.GetSizer().Add(note, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "security_key",
            "Security key"))

        # --- Look and start -----------------------------------------------
        page = wx.Panel(self.notebook)
        grid, add = labelled(page)
        self.theme_choice = add(lang.t("dialogs", "look", "Look"), lambda: wx.Choice(
            page, choices=[lang.t(
                "dialogs", "high_tech_dark",
                "High-tech dark"), lang.t(
                "dialogs", "windows_standard",
                "Windows standard")]))
        self.theme_choice.SetSelection(
            0 if (settings.get("theme") or "dark") == "dark" else 1)
        self.effects_check = add(lang.t(
            "dialogs", "visual_effects",
            "Visual effects"), lambda: wx.CheckBox(
            page, label=lang.control_label(
                "smooth_visual_effects_fades_focus_glow",
                "Smooth &visual effects: fades, focus glow, animated logo")))
        self.effects_check.SetValue(bool(settings.get("visual_effects", True)))
        self.tray_check = add(lang.t(
            "dialogs", "notification_area",
            "Notification area"), lambda: wx.CheckBox(
            page, label=lang.control_label(
                "keep_a_zkeypass_icon_in_the",
                "&Keep a ZKeypass icon in the notification area")))
        self.tray_check.SetValue(bool(settings.get("tray_enabled", True)))
        self.tray_minimise_check = add(lang.t(
            "dialogs", "minimising",
            "Minimising"), lambda: wx.CheckBox(
            page, label=lang.control_label(
                "minimise_to_the_notification_area",
                "Minimise to the notification a&rea")))
        self.tray_minimise_check.SetValue(bool(settings.get("minimize_to_tray", True)))
        self.startup_check = add(lang.t(
            "dialogs", "windows_start",
            "Windows start"), lambda: wx.CheckBox(
            page, label=lang.control_label(
                "start_zkeypass_when_i_sign_in",
                "Start ZKeypass when I sign &in to Windows")))
        self.startup_check.SetValue(bool(settings.get("run_at_startup")))
        self.startup_unlock_check = add(lang.t(
            "dialogs", "at_sign_in",
            "At sign-in"), lambda: wx.CheckBox(
            page, label=lang.control_label(
                "open_the_current_database_at_sign",
                "&Open the current database at sign-in without asking")))
        self.startup_unlock_check.SetValue(bool(settings.get("startup_unlock")))
        frame = parent if hasattr(parent, "vault") else None
        self.unlock_source = None
        if frame is not None and not getattr(frame.password, "challenge_response",
                                             None):
            self.unlock_source = (frame.vault.path, frame.password,
                                  getattr(frame.password, "keyfile", None))
        note = wx.StaticText(
            page, label=lang.t(
                "dialogs", "started_with_windows_zkeypass_waits_in",
                "Started with Windows, ZKeypass waits in the notification "
                "area, locked: Show ZKeypass asks for Windows Hello or the "
                "master password. It opens the current database without "
                "asking only when you tick that too, and only while your "
                "Windows account has a sign-in password, which Windows Hello "
                "also needs. The master password is then sealed for your "
                "Windows account alone with Windows data protection. Without "
                "a Windows password ZKeypass always starts locked. A database "
                "that needs a security key always starts locked. The look "
                "changes the next time ZKeypass starts."))
        note.Wrap(560)
        page.SetSizer(wx.BoxSizer(wx.VERTICAL))
        page.GetSizer().Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        page.GetSizer().Add(note, 0, wx.EXPAND | wx.ALL, 12)
        self.notebook.AddPage(page, lang.t(
            "dialogs", "look_and_start",
            "Look and start"))
        self.tray_check.Bind(wx.EVT_CHECKBOX, self.on_start_options)
        self.startup_check.Bind(wx.EVT_CHECKBOX, self.on_start_options)
        self.on_start_options()

        info = wx.StaticText(
            self, label=lang.t(
                "dialogs", "zkeypass_never_writes_your_master_password",
                "ZKeypass never writes your master password in readable form. "
                "Settings live in ZKeypass's data folder, so the whole ZKeypass "
                "folder can be moved or copied as one unit."))
        info.Wrap(600)
        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.notebook, 1, wx.EXPAND | wx.ALL, 8)
        root.Add(info, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 12)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizer(root)
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)

    def on_start_options(self, event=None):
        """Grey out what the other choices make meaningless."""
        self.tray_minimise_check.Enable(self.tray_check.GetValue())
        self.startup_unlock_check.Enable(self.startup_check.GetValue()
                                         and self.unlock_source is not None)

    def save_start_options(self):
        """Store the Look and start page; seal or forget the sign-in password."""
        from . import startup

        before = (self.settings.get("theme") or "dark",
                  bool(self.settings.get("visual_effects", True)))
        self.settings["theme"] = "dark" if self.theme_choice.GetSelection() == 0 \
            else "system"
        self.settings["visual_effects"] = self.effects_check.GetValue()
        self.settings["tray_enabled"] = self.tray_check.GetValue()
        self.settings["minimize_to_tray"] = self.tray_minimise_check.GetValue()
        self.settings["run_at_startup"] = self.startup_check.GetValue()

        if not self.settings["run_at_startup"]:
            if self.settings.get("startup_unlock"):
                startup.forget()
            self.settings["startup_unlock"] = False
        elif self.startup_unlock_check.IsEnabled():
            wanted = self.startup_unlock_check.GetValue()
            if wanted and not startup.windows_signin_protected():
                wanted = False
                wx.MessageBox(
                    lang.t(
                        "errors", "your_windows_account_has_no_sign",
                        "Your Windows account has no sign-in password, so "
                        "anyone at this computer would get into ZKeypass too. "
                        "ZKeypass will start with Windows, but locked. Give "
                        "your Windows account a password, or set up Windows "
                        "Hello, then tick this again."),
                    lang.t(
                        "dialogs", "start_with_windows",
                        "Start with Windows"), wx.OK | wx.ICON_WARNING, self)
            if wanted:
                path, password, keyfile = self.unlock_source
                try:
                    startup.seal(path, password, keyfile)
                except OSError as error:
                    wanted = False
                    wx.MessageBox(lang.t(
                        "errors", "windows_data_protection_did_not_seal",
                        "Windows data protection did not seal the password: "
                        "{error}",
                        error=error), lang.t(
                                      "dialogs", "start_with_windows",
                                      "Start with Windows"),
                                  wx.OK | wx.ICON_WARNING, self)
            elif self.settings.get("startup_unlock"):
                startup.forget()
            self.settings["startup_unlock"] = wanted
        if before[0] != self.settings["theme"]:
            wx.MessageBox(lang.t(
                "errors", "the_new_look_is_used_the",
                "The new look is used the next time ZKeypass starts."),
                          lang.t("dialogs", "settings", "Settings"), wx.OK | wx.ICON_INFORMATION, self)

    def on_test_key(self, event):
        from .dialogs_extras import YubiKeyDialog

        dialog = YubiKeyDialog(self, self.settings)
        dialog.ShowModal()
        dialog.Destroy()

    def on_ok(self, event):
        chosen_language = self.language_codes[
            max(0, self.language_choice.GetSelection())]
        if chosen_language != (self.settings.get("language") or ""):
            self.settings["language"] = chosen_language
            wx.MessageBox(
                lang.t("errors", "language_next_start",
                       "The new language is used the next time ZKeypass "
                       "starts."),
                lang.t("dialogs", "settings", "Settings"),
                wx.OK | wx.ICON_INFORMATION, self)
        self.settings["names_online_allowed"] = \
            self.online_names_check.GetValue()
        self.settings["announce_actions"] = \
            self.announce_modes[max(0, self.announce_choice.GetSelection())]
        for key, spinner in self.spinners.items():
            self.settings[key] = spinner.GetValue()
        self.settings["autotype_enabled"] = self.autotype_check.GetValue()
        self.settings["autotype_hotkey"] = self.hotkey_field.GetValue().strip()
        self.settings["autotype_delay_ms"] = self.delay_spinner.GetValue()
        self.settings["autotype_minimise"] = self.minimise_check.GetValue()
        self.settings["totp_hotkey_enabled"] = self.totp_hotkey_check.GetValue()
        self.settings["totp_hotkey"] = self.totp_hotkey_field.GetValue().strip()
        self.settings["totp_announce_rotation"] = \
            self.totp_announce_check.GetValue()
        self.settings["totp_show_seconds"] = self.totp_seconds_check.GetValue()
        self.settings["browser_enabled"] = self.browser_check.GetValue()
        self.settings["browser_port"] = self.browser_port.GetValue()
        self.settings["browser_ask"] = self.browser_ask.GetValue()
        self.settings["yubikey_slot"] = 1 if self.slot_choice.GetSelection() <= 0 \
            else 2
        self.settings["passkey_algorithm"] = \
            self.key_algorithm.GetStringSelection() or "ES256"
        self.save_start_options()
        event.Skip()


class ReportsDialog(wx.Dialog):
    """Password health and audit findings as a plain list of sentences."""

    def __init__(self, parent, vault, settings):
        super().__init__(parent, title=lang.t(
            "dialogs", "password_check_up",
            "Password check-up"), size=(760, 560))
        self.vault = vault
        entries = vault.all_entries_for_audit()
        self.findings = health.audit(
            entries,
            weak_bits=int(settings.get("weak_bits") or 45),
            max_age_days=int(settings.get("max_age_days") or 365),
        )
        counts = health.summarise(self.findings)

        summary_lines = [f"{count} {kind.lower()}" for kind, count in
                         sorted(counts.items())] or [lang.t(
                             "dialogs", "no_problems_found",
                             "No problems found.")]
        summary = lang.t(
            "dialogs", "checked_entries_problems_found",
            "Checked {} entries. Problems found: {}.").format(
            len(entries), ", ".join(summary_lines))

        self.summary = wx.StaticText(self, label=summary)
        self.summary.Wrap(700)
        self.listbox = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.listbox.SetName(lang.t(
            "dialogs", "check_up_findings",
            "Check-up findings"))
        self.listbox.InsertColumn(0, lang.t("dialogs", "problem", "Problem"), width=170)
        self.listbox.InsertColumn(1, lang.t("dialogs", "entry", "Entry"), width=200)
        self.listbox.InsertColumn(2, lang.t("dialogs", "detail", "Detail"), width=340)
        for row, finding in enumerate(self.findings):
            self.listbox.InsertItem(row, finding["kind"])
            self.listbox.SetItem(row, 1, finding["entry"])
            self.listbox.SetItem(row, 2, finding["detail"])

        read_button = wx.Button(self, label=lang.control_label(
            "read_selected_finding_aloud",
            "&Read selected finding aloud"))
        read_button.Bind(wx.EVT_BUTTON, self.on_read)
        copy_button = wx.Button(self, label=lang.control_label(
            "copy_full_report",
            "&Copy full report"))
        copy_button.Bind(wx.EVT_BUTTON, self.on_copy)
        close_button = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close",
            "&Close"))
        self.listbox.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.on_read)

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (read_button, copy_button, close_button):
            row.Add(button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.summary, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(self.listbox, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.ALL, 10)
        self.SetSizer(root)

    def on_read(self, event):
        row = self.listbox.GetFirstSelected()
        if row < 0:
            return
        kind = self.listbox.GetItemText(row, 0)
        entry = self.listbox.GetItemText(row, 1)
        detail = self.listbox.GetItemText(row, 2)
        wx.MessageBox(f"{kind} - {entry}. {detail}", lang.t(
            "dialogs", "finding",
            "Finding"), wx.OK, self)

    def on_copy(self, event):
        lines = [self.summary.GetLabel(), ""]
        lines += [f"{f['kind']} - {f['entry']}: {f['detail']}"
                  for f in self.findings]
        from . import clipboard

        clipboard.copy_plain("\n".join(lines))


class SshKeysDialog(wx.Dialog):
    """Load SSH private keys from the database into the built-in agent."""

    def __init__(self, parent, vault, server):
        super().__init__(parent, title=lang.t(
            "dialogs", "ssh_keys",
            "SSH keys"), size=(720, 520))
        self.vault = vault
        self.server = server
        self.key_rows = []

        intro = wx.StaticText(
            self, label=lang.t(
                "dialogs", "ssh_private_keys_kept_as_stored",
                "SSH private keys kept as stored files are listed below. "
                "Loading a key puts it into the ZKeypass agent, which answers "
                "SSH clients over the named pipe \\\\.\\pipe\\zkeypass-agent."))
        intro.Wrap(680)

        self.listbox = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.listbox.SetName(lang.t(
            "dialogs", "stored_ssh_keys",
            "Stored SSH keys"))
        self.listbox.InsertColumn(0, lang.t("dialogs", "entry", "Entry"), width=200)
        self.listbox.InsertColumn(1, lang.t("dialogs", "key_file", "Key file"), width=220)
        self.listbox.InsertColumn(2, lang.t("dialogs", "loaded", "Loaded"), width=100)
        self.refresh_keys()

        start_button = wx.Button(self, label=lang.control_label(
            "start_agent",
            "&Start agent"))
        stop_button = wx.Button(self, label=lang.control_label(
            "stop_agent",
            "S&top agent"))
        load_button = wx.Button(self, label=lang.control_label(
            "load_selected_key",
            "&Load selected key"))
        unload_button = wx.Button(self, label=lang.control_label(
            "unload_selected_key",
            "&Unload selected key"))
        start_button.Bind(wx.EVT_BUTTON, self.on_start)
        stop_button.Bind(wx.EVT_BUTTON, self.on_stop)
        load_button.Bind(wx.EVT_BUTTON, self.on_load)
        unload_button.Bind(wx.EVT_BUTTON, self.on_unload)

        buttons = wx.BoxSizer(wx.HORIZONTAL)
        for button in (start_button, stop_button, load_button, unload_button):
            buttons.Add(button, 0, wx.RIGHT, 6)

        self.fingerprints = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY,
                                        size=(-1, 90))
        self.fingerprints.SetName(lang.t(
            "dialogs", "loaded_key_fingerprints",
            "Loaded key fingerprints"))

        pipe_row = wx.BoxSizer(wx.HORIZONTAL)
        self.pipe_field = ReadOnlyField(self, value=self.server.pipe_name,
                                        style=wx.TE_READONLY)
        self.pipe_field.SetName(lang.t(
            "dialogs", "agent_pipe_name",
            "Agent pipe name"))
        copy_pipe = wx.Button(self, label=lang.control_label(
            "copy_pipe_name",
            "Copy &pipe name"))
        copy_pipe.Bind(wx.EVT_BUTTON, self.on_copy_pipe)
        pipe_row.Add(wx.StaticText(self, label=lang.t(
            "dialogs", "pipe",
            "Pipe")), 0,
                     wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 6)
        pipe_row.Add(self.pipe_field, 1, wx.RIGHT, 6)
        pipe_row.Add(copy_pipe, 0)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(intro, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(self.listbox, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(buttons, 0, wx.ALL, 10)
        root.Add(wx.StaticText(self, label=lang.t(
            "dialogs", "loaded_keys",
            "Loaded keys")), 0, wx.LEFT, 10)
        root.Add(self.fingerprints, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(pipe_row, 0, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(root)
        self.refresh_fingerprints()

    def refresh_keys(self):
        self.listbox.DeleteAllItems()
        self.key_rows = []
        for entry in self.vault.entries():
            for attachment in self.vault.attachments(entry["id"]):
                name = attachment["name"].lower()
                if not (name.endswith(".key") or name.endswith(".pem")
                        or name.startswith("id_") or "private" in name
                        or name.endswith(".ppk")):
                    continue
                self.key_rows.append((entry, attachment))
        for row, (entry, attachment) in enumerate(self.key_rows):
            self.listbox.InsertItem(row, entry["title"])
            self.listbox.SetItem(row, 1, attachment["name"])
            loaded = (lang.t("dialogs", "yes_word", "yes")
                      if self.server.has_key(attachment["id"]) else "")
            self.listbox.SetItem(row, 2, loaded)

    def refresh_fingerprints(self):
        lines = []
        for key_id, info in self.server.loaded_keys().items():
            lines.append(f"{info['name']}: {info['fingerprint']}")
        self.fingerprints.SetValue("\n".join(lines))

    def on_start(self, event):
        try:
            self.server.start()
            wx.MessageBox(lang.t(
                "errors", "the_agent_is_listening_on",
                "The agent is listening on {pipe_name}.",
                pipe_name=self.server.pipe_name),
                          lang.t("dialogs", "ssh_agent", "SSH agent"), wx.OK | wx.ICON_INFORMATION, self)
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_start_the_agent",
                "Could not start the agent: {error}",
                error=error), lang.t(
                "dialogs", "ssh_agent",
                "SSH agent"),
                          wx.OK | wx.ICON_ERROR, self)

    def on_stop(self, event):
        self.server.stop()
        self.refresh_keys()
        self.refresh_fingerprints()

    def on_load(self, event):
        row = self.listbox.GetFirstSelected()
        if row < 0:
            return
        entry, attachment = self.key_rows[row]
        data = self.vault.attachment_data(attachment["id"])
        try:
            info = self.server.load_key(attachment["id"], attachment["name"], data)
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "that_file_could_not_be_loaded",
                "That file could not be loaded as an SSH key: {error}",
                error=error),
                          lang.t("dialogs", "ssh_agent", "SSH agent"), wx.OK | wx.ICON_ERROR, self)
            return
        self.refresh_keys()
        self.refresh_fingerprints()
        wx.MessageBox(lang.t(
            "errors", "loaded",
            "Loaded {name}.\n{fingerprint}",
            name=attachment['name'],
            fingerprint=info['fingerprint']),
                      lang.t("dialogs", "ssh_agent", "SSH agent"), wx.OK | wx.ICON_INFORMATION, self)

    def on_unload(self, event):
        row = self.listbox.GetFirstSelected()
        if row < 0:
            return
        _, attachment = self.key_rows[row]
        self.server.unload_key(attachment["id"])
        self.refresh_keys()
        self.refresh_fingerprints()

    def on_copy_pipe(self, event):
        from . import clipboard

        clipboard.copy_plain(self.server.pipe_name)
