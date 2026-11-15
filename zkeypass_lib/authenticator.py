"""The Authenticator page.

A dedicated, keyboard-first page listing every entry that carries a TOTP
setup key, with a live six digit code beside each account.  Everything is ordinary
wxPython: a report list, a search box, a group filter and named buttons, so
NVDA and JAWS read the account name, the code and the seconds left without any
custom drawing.

Keys while the account list has the focus:

    Enter or Control T   copy the selected code
    R                    read the setup key of the selected account aloud
    S                    copy the setup key
    C                    copy the code
    E                    edit the selected entry
    F5                   refresh the list
    Space                repeat the selected account and its code
"""

import time

import wx

from . import totp
from . import lang

# Settings key, heading, width, View menu label.  Account is always shown;
# the View menu turns the others on and off.
COLUMNS = (("account", "Account", 210, "&Account"),
           ("code", "Code", 90, "&Code"),
           ("valid", "Valid", 140, "&Valid for"),
           ("group", "Group", 130, "&Group"),
           ("username", "Username", 150, "&User name"))
_SPOKEN = {"account": "account", "code": "code", "valid": "seconds valid",
           "group": "group", "username": "username"}


class AuthenticatorPage(wx.Panel):
    """Live codes for every entry that has a setup key."""

    def __init__(self, parent, frame):
        super().__init__(parent)
        self.frame = frame
        self.vault = frame.vault
        self.accounts = []
        self.last_codes = {}
        self.last_announced = None

        self.heading = wx.StaticText(
            self, label=lang.control_label(
                "accounts_with_verification_codes",
                "&Accounts with verification codes"))
        self.summary = wx.StaticText(self, label="")
        self.summary.SetName(lang.t(
            "dialogs", "authenticator_summary",
            "Authenticator summary"))

        self.filter_box = wx.SearchCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.filter_box.SetName(lang.t(
            "dialogs", "search_accounts",
            "Search accounts"))
        self.filter_box.SetDescriptiveText(lang.t(
            "dialogs", "search_accounts",
            "Search accounts"))

        self.group_label = wx.StaticText(self, label=lang.control_label(
            "show",
            "&Show"))
        self.group_choice = wx.Choice(self)
        self.group_choice.SetName(lang.t(
            "dialogs", "which_accounts_to_show",
            "Which accounts to show"))

        self.account_list = wx.ListCtrl(
            self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.build_columns()

        self.detail_label = wx.StaticText(self, label="")
        self.detail_label.SetName(lang.t(
            "dialogs", "selected_account_details",
            "Selected account details"))

        button_row = wx.BoxSizer(wx.HORIZONTAL)
        self.buttons = {}
        for key, label, handler in (
            ("copy", lang.menu_label("copy_code_enter", "&Copy code\tEnter"), self.on_copy_code),
            ("read", lang.menu_label(
                "read_code_aloud_space",
                "&Read code aloud\tSpace"), self.on_read_code),
            ("seed", lang.menu_label("show_setup_key_r", "Show setup &key\tR"), self.on_show_seed),
            ("copy_seed", lang.menu_label(
                "copy_setup_key_s",
                "Copy setup k&ey\tS"), self.on_copy_seed),
            ("edit", lang.menu_label(
                "edit_this_entry_e",
                "&Edit this entry\tE"), self.on_edit_entry),
            ("refresh", lang.menu_label("refresh_f5", "Re&fresh\tF5"), self.on_refresh),
        ):
            # A tab in a button label is not drawn as a gap, so the key goes
            # in brackets after the words: "Copy code (Enter)".
            words, _tab, keys = label.partition("\t")
            button = wx.Button(self, label=f"{words} ({keys})" if keys else words)
            button.SetName(words.replace("&", ""))
            button.Bind(wx.EVT_BUTTON, handler)
            button_row.Add(button, 0, wx.RIGHT, 6)
            self.buttons[key] = button

        hint = wx.StaticText(
            self, label=lang.t(
                "dialogs", "codes_refresh_every_second_while_this",
                "Codes refresh every second while this page is open. Enter "
                "or Control T copies the selected code, and the clipboard is "
                "cleared again after the number of seconds set in Settings."))
        hint.Wrap(600)

        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self.filter_box, 1, wx.EXPAND | wx.RIGHT, 6)
        top.Add(self.group_label, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 4)
        top.Add(self.group_choice, 0, wx.ALIGN_CENTER_VERTICAL)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.heading, 0, wx.ALL, 6)
        root.Add(self.summary, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 6)
        root.Add(top, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 6)
        root.Add(self.account_list, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 6)
        root.Add(self.detail_label, 0, wx.EXPAND | wx.ALL, 6)
        root.Add(button_row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 6)
        root.Add(hint, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 6)
        self.SetSizer(root)

        self.filter_box.Bind(wx.EVT_TEXT, lambda event: self.refresh())
        self.group_choice.Bind(wx.EVT_CHOICE, lambda event: self.refresh())
        self.account_list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_selected)
        self.account_list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.on_copy_code)
        self.account_list.Bind(wx.EVT_KEY_DOWN, self.on_key)
        self.account_list.Bind(wx.EVT_CONTEXT_MENU, self.on_context_menu)
        self.refresh()

    # ------------------------------------------------------------------ data

    def build_columns(self):
        """Lay out the columns chosen in the View menu."""
        self.account_list.ClearAll()
        chosen = self.frame.settings.get("authenticator_columns")
        if not isinstance(chosen, list):
            chosen = [key for key, *_rest in COLUMNS[1:]]
        self.column_keys = [COLUMNS[0][0]] + [
            key for key, *_rest in COLUMNS[1:] if key in chosen]
        for key, caption, width, _label in COLUMNS:
            if key in self.column_keys:
                self.account_list.InsertColumn(
                    self.account_list.GetColumnCount(),
                    lang.t("main_ui", "auth_column_" + key, caption), width=width)
        self.account_list.SetName(lang.t(
            "main_ui", "auth_list_name",
            "Authenticator accounts, columns {columns}",
            columns=", ".join(lang.t("main_ui", "auth_column_spoken_" + key,
                                     _SPOKEN[key])
                              for key in self.column_keys)))

    def cell(self, key, entry, code, moment):
        if key == "account":
            return self.account_label(entry)
        if key == "code":
            return totp.format_code(code)
        if key == "valid":
            return self.seconds_text(entry, moment)
        if key == "group":
            return entry.get("group_name") or ""
        if key == "username":
            return entry.get("username") or ""
        return ""

    def column_of(self, key):
        return self.column_keys.index(key) if key in self.column_keys else -1

    def refresh(self, keep_selection=True):
        """Rebuild the account rows from the database."""
        previous = self.selected_entry_id() if keep_selection else None
        # Read the current choice before rebuilding the list: filling a
        # wx.Choice again clears its selection.
        current = self.group_choice.GetSelection()
        labels = [lang.t("dialogs", "all_accounts", "All accounts"), lang.t("dialogs", "favourites", "Favourites")]
        self.group_values = [None, "favourites"]
        for group in self.frame.vault.groups():
            labels.append(group["name"])
            self.group_values.append(group["id"])
        self.group_choice.Set(labels)
        if not 0 <= current < len(labels):
            current = 0
        self.group_choice.SetSelection(current)

        chosen = self.group_values[current]
        search = self.filter_box.GetValue().strip()
        self.accounts = []
        for entry in self.frame.vault.entries_with_totp(search=search or None):
            if chosen == "favourites" and not entry.get("favourite"):
                continue
            if isinstance(chosen, int) and entry.get("group_id") != chosen:
                continue
            self.accounts.append(entry)

        self.account_list.DeleteAllItems()
        self.last_codes = {}
        moment = time.time()
        for row, entry in enumerate(self.accounts):
            code = totp.current_code(entry, timestamp=moment)
            for column, key in enumerate(self.column_keys):
                text = self.cell(key, entry, code, moment)
                if column == 0:
                    self.account_list.InsertItem(row, text)
                else:
                    self.account_list.SetItem(row, column, text)
            self.last_codes[entry["id"]] = code

        if self.accounts:
            index = 0
            for row, entry in enumerate(self.accounts):
                if entry["id"] == previous:
                    index = row
                    break
            self.account_list.Select(index)
            self.account_list.Focus(index)
            self.describe(self.accounts[index])
        else:
            self.describe(None)

        self.summary.SetLabel(self.summary_text())
        self.enable_buttons(bool(self.accounts))
        layout = self.GetSizer()
        if layout:
            layout.Layout()
        return self.accounts

    def summary_text(self):
        count = len(self.accounts)
        if not count:
            return (lang.t(
                "dialogs", "no_entries_have_a_setup_key",
                "No entries have a setup key yet. Add one on the "
                "Authenticator page of any entry."))
        return lang.plural(
            "dialogs", "accounts_with_codes", count,
            "{count} account with verification codes. Press Enter to copy a "
            "code.",
            "{count} accounts with verification codes. Press Enter to copy a "
            "code.")

    def account_label(self, entry):
        """Issuer or title first, then the account name, for easy listening."""
        from . import names

        title = names.display_title(entry)
        username = (entry.get("username") or "").strip()
        if title.startswith("otpauth://"):
            parsed = totp.parse_otpauth(title) or {}
            label = parsed.get("issuer") or parsed.get("account") or title
            title = label
        if username and username not in title:
            return f"{title}, {username}"
        return title

    def seconds_text(self, entry, moment=None):
        left = totp.seconds_remaining_for(entry, moment)
        if left <= 5:
            return lang.t(
                "dialogs", "seconds_expiring",
                "{left} seconds, expiring",
                left=left)
        return lang.t("dialogs", "seconds", "{left} seconds", left=left)

    def enable_buttons(self, enabled):
        for key, button in self.buttons.items():
            if key == "refresh":
                continue
            button.Enable(enabled)

    # -------------------------------------------------------------- selection

    def selected_entry_id(self):
        row = self.account_list.GetFirstSelected()
        if 0 <= row < len(self.accounts):
            return self.accounts[row]["id"]
        return None

    def selected_entry(self):
        """The highlighted account, or the first one when none is highlighted."""
        row = self.account_list.GetFirstSelected()
        if not 0 <= row < len(self.accounts):
            if self.accounts:
                self.account_list.Select(0)
                self.account_list.Focus(0)
                row = 0
            else:
                return None
        return self.accounts[row]

    def on_selected(self, event):
        entry = self.selected_entry()
        self.describe(entry)

    def describe(self, entry):
        """Put a plain sentence on screen; screen readers read it in order."""
        if not entry:
            self.detail_label.SetLabel(
                lang.t(
                    "dialogs", "no_account_selected_use_the_search",
                    "No account selected. Use the search box, or add a setup "
                    "key to an entry."))
            return
        code = totp.current_code(entry)
        left = totp.seconds_remaining_for(entry)
        self.detail_label.SetLabel(
            lang.t(
                "dialogs", "selected_code_valid_for_seconds_press",
                "Selected: {account_label}. Code {code}. Valid for {left} "
                "seconds. Press Enter to copy it.",
                account_label=self.account_label(entry),
                code=totp.format_code(code),
                left=left))

    def on_read_code(self, event=None):
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        code = totp.current_code(entry)
        left = totp.seconds_remaining_for(entry)
        self.frame.SetStatus(
            lang.t(
                "actions_announcements", "code_valid_for_seconds",
                "{account_label}: code {code}, valid for {left} seconds.",
                account_label=self.account_label(entry),
                code=totp.format_code(code),
                left=left))
        self.describe(entry)

    def on_context_menu(self, event=None):
        """Copy the code and the other actions, as a menu at the account."""
        entry = self.selected_entry()
        if not entry:
            return
        menu = wx.Menu()
        for label, handler in (
            (lang.menu_label("copy_code_enter", "&Copy code\tEnter"), self.on_copy_code),
            (lang.menu_label(
                "read_the_code_aloud_space",
                "&Read the code aloud\tSpace"), self.on_read_code),
            (lang.menu_label("copy_the_user_name", "Copy the &user name"), self.on_copy_username),
            (lang.menu_label("copy_the_password", "Copy the pass&word"), self.on_copy_password),
            (lang.menu_label("show_the_setup_key_r", "Show the setup &key\tR"), self.on_show_seed),
            (lang.menu_label("copy_the_setup_key_s", "Copy the setup k&ey\tS"), self.on_copy_seed),
            (lang.menu_label("edit_this_entry_e", "&Edit this entry\tE"), self.on_edit_entry),
            (lang.menu_label("rename", "Re&name..."), self.on_rename),
        ):
            item = menu.Append(wx.ID_ANY, label)
            menu.Bind(wx.EVT_MENU, handler, item)
        self.account_list.PopupMenu(menu)
        menu.Destroy()

    def _with_entry(self, action):
        """Run a main window action on the account selected here."""
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        self.frame.current_entry_id = entry["id"]
        action()

    def on_copy_username(self, event=None):
        self._with_entry(lambda: self.frame.copy_field("username"))

    def on_copy_password(self, event=None):
        self._with_entry(lambda: self.frame.copy_field("password"))

    def on_rename(self, event=None):
        self._with_entry(self.frame.on_rename_entry)
        self.refresh()

    def on_key(self, event):
        code = event.GetKeyCode()
        control = event.ControlDown()
        if code in (wx.WXK_RETURN, wx.WXK_NUMPAD_ENTER) or (control and code == ord("T")):
            self.on_copy_code(event)
        elif code == ord("C") and not control:
            self.on_copy_code(event)
        elif code == ord("R") and not control:
            self.on_show_seed(event)
        elif code == ord("S") and not control:
            self.on_copy_seed(event)
        elif code == ord("E") and not control:
            self.on_edit_entry(event)
        elif code in (wx.WXK_F5, wx.WXK_SPACE):
            if code == wx.WXK_SPACE:
                self.on_read_code(event)
            else:
                self.on_refresh(event)
        else:
            event.Skip()

    # ---------------------------------------------------------------- actions

    def on_copy_code(self, event=None):
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        code = totp.current_code(entry)
        if not code:
            self.frame.SetStatus(
                lang.t(
                    "actions_announcements", "that_setup_key_could_not_be",
                    "That setup key could not be read. Check the setup key "
                    "on the Authenticator page of the entry."))
            return
        self.frame.set_clipboard(code)
        left = totp.seconds_remaining_for(entry)
        self.frame.SetStatus(
            lang.t(
                "actions_announcements", "code_copied_for_valid_for_seconds",
                "Code {code} copied for {account_label}. Valid for {left} "
                "seconds. Clipboard clears in {seconds} seconds.",
                code=totp.format_code(code),
                account_label=self.account_label(entry),
                left=left,
                seconds=int(self.frame.settings.get('clipboard_clear_seconds') or 0)))

    def on_show_seed(self, event=None):
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        seed = entry.get("totp_secret") or ""
        wx.MessageBox(
            lang.t(
                "errors", "account_setup_key_digits_period_seconds",
                "Account: {account_label}\n\nSetup key: {setup_key}\n\n"
                "Digits: {totp_digits}\nPeriod: {totp_period} seconds\n"
                "Algorithm: {totp_algorithm}\n\nThe setup key is the secret "
                "that creates every code. Keep it private.",
                account_label=self.account_label(entry),
                setup_key=totp.group_secret(seed),
                totp_digits=entry.get('totp_digits') or 6,
                totp_period=entry.get('totp_period') or 30,
                totp_algorithm=entry.get('totp_algorithm') or 'SHA1'),
            lang.t(
                "dialogs", "authenticator_setup_key",
                "Authenticator setup key"), wx.OK | wx.ICON_INFORMATION, self)

    def on_copy_seed(self, event=None):
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        seed = entry.get("totp_secret") or ""
        if not seed:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "that_account_has_no_setup_key",
                "That account has no setup key stored."))
            return
        self.frame.set_clipboard(seed)
        self.frame.SetStatus(
            lang.t(
                "actions_announcements", "setup_key_for_copied_clipboard_clears",
                "Setup key for {account_label} copied. Clipboard clears in "
                "{seconds} seconds.",
                account_label=self.account_label(entry),
                seconds=int(self.frame.settings.get('clipboard_clear_seconds') or 0)))

    def on_edit_entry(self, event=None):
        entry = self.selected_entry()
        if not entry:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_account_first",
                "Select an account first."))
            return
        from .dialogs import EntryDialog

        dialog = EntryDialog(self.frame, self.frame.vault, entry["id"])
        dialog.notebook.SetSelection(2)
        if dialog.ShowModal() == wx.ID_OK:
            self.frame.auto_save()
        dialog.Destroy()
        self.refresh()

    def on_refresh(self, event=None):
        self.refresh()
        self.frame.SetStatus(self.summary_text())

    def focus_list(self):
        self.account_list.SetFocus()
        entry = self.selected_entry()
        if entry:
            self.describe(entry)
            # The list taking the focus is read by the screen reader already.
            self.frame.SetStatus(self.summary_text(), speak=False)

    # ------------------------------------------------------------ live ticking

    def tick(self):
        """Called once a second by the main window while the database is open."""
        if not self.accounts:
            return
        moment = time.time()
        # Only say a new code while this page is in front of the user.
        announce = (bool(self.frame.settings.get("totp_announce_rotation"))
                    and self.IsShownOnScreen() and self.frame.IsActive())
        show_seconds = self.frame.settings.get("totp_show_seconds", True)
        selected = self.selected_entry_id()
        code_column = self.column_of("code")
        valid_column = self.column_of("valid")
        for row, entry in enumerate(self.accounts):
            code = totp.current_code(entry, timestamp=moment)
            formatted = totp.format_code(code)
            if self.last_codes.get(entry["id"]) != code:
                if announce and entry["id"] == selected and code:
                    self.frame.SetStatus(
                        lang.t(
                            "actions_announcements", "new_code_for",
                            "New code {formatted} for {account_label}.",
                            formatted=formatted,
                            account_label=self.account_label(entry)), interrupt=False)
            if (code_column > 0
                    and self.account_list.GetItemText(row, code_column) != formatted):
                self.account_list.SetItem(row, code_column, formatted)
            self.last_codes[entry["id"]] = code
            if show_seconds and valid_column > 0:
                text = self.seconds_text(entry, moment)
                if self.account_list.GetItemText(row, valid_column) != text:
                    self.account_list.SetItem(row, valid_column, text)
        if self.IsShown():
            entry = self.selected_entry()
            if entry:
                self.describe(entry)
