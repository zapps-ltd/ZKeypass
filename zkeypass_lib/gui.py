"""Main application window.

Layout is deliberately plain and keyboard-first: a native menu bar, a group
list, an entry list, and a read-only details pane made only of ordinary
Windows controls, so NVDA and JAWS announce everything without extra work.
"""

import os
import time

import wx

from . import autotype, autotype_store, health, names, paths, speech, theme, totp
from .dialogs import (EntryDialog, GeneratorDialog, ReadOnlyField, ReportsDialog,
                      SettingsDialog, SshKeysDialog, ask_yes_no)
from .dialogs_extras import (AutoTypeDialog, AutoTypeEditDialog, BrowserDialog,
                             PasskeysDialog, YubiKeyDialog)
from .authenticator import AuthenticatorPage
from .convert_dialogs import ExportDialog, SaveAsDialog
from .settings import Settings, remember_folder, remember_recent
from .sshagent import SshAgentServer
from . import lang

# The entry list columns: settings key, heading, width, and the label used in
# the View menu.  Name is always shown; the View menu turns the rest on and off.
ENTRY_COLUMNS = (
    ("title", "Name", 220, "&Name"),
    ("username", "Username", 150, "&User name"),
    ("site", "Site", 160, "&Site"),
    ("group", "Group", 120, "&Group"),
    ("totp", "Verification code", 100, "&Verification code"),
    ("modified", "Changed", 120, "Date &changed"),
)
COLUMN_NAMES = {"title": "name", "username": "user name", "site": "site",
                "group": "group", "totp": "verification code",
                "modified": "date changed", "code": "code",
                "valid": "valid for", "account": "account"}
# Columns the list can be sorted by; a verification code changes too often.
SORT_COLUMNS = ("title", "username", "site", "group", "modified")


class MainFrame(wx.Frame):
    def __init__(self, vault, password, settings=None):
        super().__init__(None, title=lang.t(
            "dialogs", "zkeypass_2",
            "ZKeypass - {name}",
            name=os.path.basename(vault.path or 'memory')),
                         size=tuple(Settings.load().get("window_size")))
        if lang.is_rtl():
            self.SetLayoutDirection(wx.Layout_RightToLeft)
        self.vault = vault
        self.password = password
        self.settings = settings or Settings.load()
        self.filtered_entries = []
        self.current_entry_id = None
        self.last_totp_code = ""
        self.clipboard_timer = None
        self.lock_timer = None
        self.ssh_server = SshAgentServer()
        self.browser_server = None
        self.browser_bridge = None
        self.hotkey_id = None
        self.totp_hotkey_id = None
        self.autotype_in_progress = False
        # Why the window closes: "quit" ends ZKeypass, "lock" goes back to the
        # start window, "autolock" leaves it locked in the notification area.
        self.close_reason = "quit"

        self._build_menu()
        self._build_layout()
        self._bind_events()
        self.refresh_groups()
        self.refresh_entries()
        self.SetStatusBar(wx.StatusBar(self))
        self.update_status()
        codes = len(self.vault.entries_with_totp())
        if codes:
            self.SetStatus(
                self.last_status + lang.plural(
                    "actions_announcements", "press_control_2_for_the_authenticator",
                    codes,
                    " Press Control 2 for the Authenticator page, which "
                    "lists the {count} account with a code.",
                    " Press Control 2 for the Authenticator page, which "
                    "lists the {count} accounts with a code."))
        theme.prepare(self, fade=False)
        speech.set_mode(self.settings.get("announce_actions", "auto"))
        self.Raise()

        self.totp_timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.on_totp_tick, self.totp_timer)
        self.totp_timer.Start(1000)
        self.restart_auto_lock()
        self.register_hotkey()
        self.register_totp_hotkey()
        if self.settings.get("browser_enabled"):
            try:
                self.start_browser_server()
            except Exception:
                pass

    # -------------------------------------------------------------- interface

    def _build_menu(self):
        """The menu bar.  Every item is reachable with Alt plus its letter."""
        file_menu = wx.Menu()
        for item_id, label, shortcut, handler in (
            (wx.ID_NEW, lang.menu_label(
                "new_database_ctrl_n",
                "&New database...\tCtrl+N"), "", self.on_new_vault),
            (wx.ID_OPEN, lang.menu_label(
                "open_database_ctrl_o",
                "&Open database...\tCtrl+O"), "", self.on_open_vault),
            (wx.ID_ANY, lang.menu_label(
                "copy_a_database_into_zkeypass_and",
                "&Copy a database into ZKeypass and open it..."),
             lang.t(
                 "dialogs", "copy_a_kdbx_or_zkp_into",
                 "Copy a .kdbx or .zkp into ZKeypass's data folder and open "
                 "the copy"), None),
        ):
            if handler is None:
                entry = file_menu.Append(item_id, label)
                entry.SetHelp(lang.t(
                    "dialogs", "copy_a_kdbx_or_zkp_into",
                    "Copy a .kdbx or .zkp into ZKeypass's data folder and open "
                    "the copy"))
                self.Bind(wx.EVT_MENU, self.on_open_copy, entry)
                continue
            entry = file_menu.Append(item_id, label, shortcut)
            self.Bind(wx.EVT_MENU, handler, entry)
        self.recent_menu = wx.Menu()
        file_menu.AppendSubMenu(self.recent_menu, lang.menu_label(
            "recent_databases",
            "&Recent databases"))
        file_menu.AppendSeparator()
        for label, handler in (
            (lang.menu_label("save_database_ctrl_s", "&Save database\tCtrl+S"), self.on_save_vault),
            (lang.menu_label("save_a_copy_as", "Save a copy &as..."), lambda event: self.on_save_as()),
            (lang.menu_label(
                "export_to_a_readable_file",
                "&Export to a readable file..."), lambda event: self.on_export_vault()),
        ):
            item = file_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        file_menu.AppendSeparator()
        hello_item = file_menu.Append(
            wx.ID_ANY, lang.menu_label(
                "windows_hello_for_this_database",
                "Windows &Hello for this database..."),
            lang.menu_label(
                "open_this_database_with_your_pin",
                "Open this database with your PIN, fingerprint or face"))
        self.Bind(wx.EVT_MENU, self.on_windows_hello, hello_item)
        lock_item = file_menu.Append(wx.ID_ANY, lang.menu_label(
            "lock_and_close_now_ctrl_l",
            "&Lock and close now\tCtrl+L"),
                                     lang.menu_label(
                                         "close_the_database_and_ask_for",
                                         "Close the database and ask for the "
                                         "password again next time"))
        self.Bind(wx.EVT_MENU, self.on_close_vault, lock_item)
        file_menu.AppendSeparator()
        hide_item = file_menu.Append(
            wx.ID_ANY, lang.menu_label(
                "minimise_to_the_notification_area",
                "&Minimise to the notification area"),
            lang.menu_label(
                "hide_this_window_zkeypass_stays_in",
                "Hide this window; ZKeypass stays in the notification area"))
        self.Bind(wx.EVT_MENU, lambda event: self.Iconize(True), hide_item)
        quit_item = file_menu.Append(wx.ID_EXIT, lang.menu_label(
            "quit_zkeypass_ctrl_shift_q",
            "&Quit ZKeypass\tCtrl+Shift+Q"),
                                     lang.menu_label(
                                         "save_close_the_database_and_end",
                                         "Save, close the database and end "
                                         "ZKeypass"))
        self.Bind(wx.EVT_MENU, self.on_quit, quit_item)

        entry_menu = wx.Menu()
        for label, handler in (
            (lang.menu_label(
                "new_entry_ctrl_shift_n",
                "&New entry\tCtrl+Shift+N"), self.on_new_entry),
            (lang.menu_label("edit_entry_enter", "&Edit entry\tEnter"), self.on_edit_entry),
            (lang.menu_label(
                "delete_entry_ctrl_delete",
                "&Delete entry\tCtrl+Delete"), self.on_delete_entry),
            (lang.menu_label("duplicate_entry", "D&uplicate entry"), self.on_duplicate_entry),
            (lang.menu_label("rename_entry_f2", "Re&name entry...\tF2"), self.on_rename_entry),
            (lang.menu_label("set_the_user_name", "Set the user na&me..."), self.on_set_username),
            (lang.menu_label(
                "move_to_another_group",
                "Move to another &group..."), self.on_move_entry),
            (lang.menu_label(
                "suggest_names_for_entries_without_one",
                "Suggest names for entries &without one..."), self.on_suggest_names),
            (lang.menu_label(
                "toggle_favourite_ctrl_f",
                "Toggle &favourite\tCtrl+F"), self.on_toggle_favourite),
        ):
            item = entry_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        entry_menu.AppendSeparator()
        for label, handler in (
            (lang.menu_label("copy_username_ctrl_b", "Copy &username\tCtrl+B"), lambda event: self.copy_field("username")),
            (lang.menu_label(
                "copy_password_ctrl_shift_c",
                "Copy &password\tCtrl+Shift+C"), lambda event: self.copy_field("password")),
            (lang.menu_label("show_password", "Show pass&word..."), self.on_show_password),
            (lang.menu_label(
                "copy_verification_code_of_this_entry",
                "Copy &verification code of this entry\tCtrl+T"),
             lambda event: self.copy_field("totp")),
            (lang.menu_label(
                "copy_code_of_selected_account_ctrl",
                "Copy code of selected &account\tCtrl+Shift+T"),
             lambda event: self.copy_selected_account_code()),
            (lang.menu_label(
                "open_the_authenticator_page_ctrl_2",
                "Open the &Authenticator page\tCtrl+2"),
             lambda event: self.show_authenticator()),
            (lang.menu_label("copy_url_ctrl_u", "Copy &URL\tCtrl+U"), lambda event: self.copy_field("url")),
            (lang.menu_label("clear_clipboard_now", "&Clear clipboard now"), self.clear_clipboard),
        ):
            item = entry_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        entry_menu.AppendSeparator()
        for label, handler in ((lang.menu_label(
            "add_a_file_to_this_entry",
            "Add a file to this entr&y..."), self.on_attach_file),
                               (lang.menu_label(
                                   "save_a_stored_file_to_disk",
                                   "&Save a stored file to disk..."), self.on_save_attachment)):
            item = entry_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        entry_menu.AppendSeparator()
        for label, handler in (
            (lang.menu_label(
                "auto_type_this_entry_ctrl_shift",
                "Auto-&type this entry\tCtrl+Shift+A"), self.on_autotype_entry),
            (lang.menu_label(
                "auto_type_settings_for_this_entry",
                "Auto-&type settings for this entry"), self.on_autotype_settings),
            (lang.menu_label(
                "passkeys_for_this_entry",
                "&Passkeys for this entry..."), self.on_passkeys),
        ):
            item = entry_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)

        twofa_menu = wx.Menu()
        for label, handler in (
            (lang.menu_label(
                "go_to_the_authenticator_page_ctrl",
                "&Go to the Authenticator page\tCtrl+2"),
             lambda event: self.show_authenticator()),
            (lang.menu_label(
                "copy_the_selected_account_code_ctrl",
                "&Copy the selected account code\tCtrl+Shift+T"),
             lambda event: self.copy_selected_account_code()),
            (lang.menu_label(
                "read_the_selected_account_aloud",
                "&Read the selected account aloud"),
             lambda event: self.authenticator.on_read_code()),
            (lang.menu_label(
                "add_a_setup_key_to_the",
                "Add a setup &key to the selected entry..."),
             lambda event: self.on_add_secret()),
            (lang.menu_label(
                "refresh_the_account_list_f5",
                "&Refresh the account list\tF5"),
             lambda event: self.authenticator.on_refresh()),
            (lang.menu_label(
                "show_the_setup_key_of_the",
                "Show the setup &key of the selected account\tR"),
             lambda event: self.authenticator.on_show_seed()),
        ):
            item = twofa_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)

        view_menu = self._build_view_menu()

        tools_menu = wx.Menu()
        for label, handler in (
            (lang.menu_label(
                "auto_type_a_chosen_entry_ctrl",
                "&Auto-type a chosen entry\tCtrl+Alt+A"), self.on_autotype),
            (lang.menu_label("browser_integration", "&Browser integration..."), self.on_browser),
            (lang.menu_label("security_key", "Security &key..."), self.on_security_key),
            (lang.menu_label(
                "password_generator_ctrl_g",
                "Password &generator\tCtrl+G"), self.on_generator),
            (lang.menu_label(
                "password_check_up_ctrl_r",
                "Password &check-up\tCtrl+R"), self.on_report),
            (lang.menu_label("ssh_keys_ctrl_k", "&SSH keys...\tCtrl+K"), self.on_ssh_keys),
        ):
            item = tools_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        # Every import sits in one submenu, named by the program the file
        # came from, so the Tools menu stays short when read item by item.
        import_menu = wx.Menu()
        for label, handler in (
            (lang.menu_label("csv_file", "&CSV file..."), self.on_import_csv),
            (lang.menu_label("bitwarden", "&Bitwarden..."), self.on_import_bitwarden),
            (lang.menu_label("1password_1pux", "1Password 1P&UX..."), self.on_import_1pux),
            (lang.menu_label("keepass_1", "&KeePass 1..."), self.on_import_keepass1),
            (lang.menu_label("password_safe", "&Password Safe..."), self.on_import_pwsafe),
            (lang.menu_label("1password_opvault", "1Password &OPVault..."), self.on_import_opvault),
            (lang.menu_label("proton_pass", "Pro&ton Pass..."), self.on_import_protonpass),
            (lang.menu_label("enpass", "&Enpass..."), self.on_import_enpass),
            (lang.menu_label("dashlane", "&Dashlane..."), self.on_import_dashlane),
        ):
            item = import_menu.Append(wx.ID_ANY, label)
            self.Bind(wx.EVT_MENU, handler, item)
        tools_menu.AppendSubMenu(import_menu, lang.menu_label(
            "import_entries_from",
            "&Import entries from"))
        tools_menu.AppendSeparator()
        settings_item = tools_menu.Append(wx.ID_PREFERENCES, lang.menu_label(
            "settings",
            "S&ettings..."))
        self.Bind(wx.EVT_MENU, self.on_settings, settings_item)

        help_menu = wx.Menu()
        hotkeys_item = help_menu.Append(wx.ID_ANY, lang.menu_label(
            "hotkeys_list_f1",
            "&Hotkeys list...\tF1"),
                                        lang.menu_label(
                                            "every_keyboard_shortcut_in_zkeypass",
                                            "Every keyboard shortcut in ZKeypass"))
        self.Bind(wx.EVT_MENU, self.on_hotkeys_list, hotkeys_item)
        details_item = help_menu.Append(
            wx.ID_ANY, lang.menu_label(
                "database_and_encryption_details",
                "&Database and encryption details"))
        self.Bind(wx.EVT_MENU, self.on_details, details_item)
        about_item = help_menu.Append(wx.ID_ABOUT, lang.menu_label(
            "about_zkeypass",
            "&About ZKeypass"))
        self.Bind(wx.EVT_MENU, self.on_about, about_item)

        bar = wx.MenuBar()
        bar.Append(file_menu, lang.menu_label("database", "&Database"))
        bar.Append(entry_menu, lang.menu_label("entry", "&Entry"))
        bar.Append(view_menu, lang.menu_label("view", "&View"))
        bar.Append(twofa_menu, lang.menu_label(
            "authenticator",
            "&Authenticator"))
        bar.Append(tools_menu, lang.menu_label("tools", "&Tools"))
        bar.Append(help_menu, lang.menu_label("help", "&Help"))
        self.SetMenuBar(bar)

    def _build_view_menu(self):
        """Sorting, and which columns each list shows.  Alt+V."""
        sort_menu = wx.Menu()
        self.sort_items = {}
        for key, _heading, _width, label in ENTRY_COLUMNS:
            if key not in SORT_COLUMNS:
                continue
            item = sort_menu.AppendRadioItem(
                wx.ID_ANY, lang.menu_label("view_column_" + key, label))
            self.Bind(wx.EVT_MENU, lambda event, key=key: self.set_sort(key), item)
            self.sort_items[key] = item
        sort_menu.AppendSeparator()
        self.ascending_item = sort_menu.AppendRadioItem(
            wx.ID_ANY, lang.menu_label(
                "ascending_a_to_z_and_oldest",
                "&Ascending, A to Z and oldest first"))
        self.descending_item = sort_menu.AppendRadioItem(
            wx.ID_ANY, lang.menu_label(
                "descending_z_to_a_and_newest",
                "&Descending, Z to A and newest first"))
        self.Bind(wx.EVT_MENU, lambda event: self.set_sort(descending=False),
                  self.ascending_item)
        self.Bind(wx.EVT_MENU, lambda event: self.set_sort(descending=True),
                  self.descending_item)

        columns_menu = wx.Menu()
        self.column_items = {}
        for key, _heading, _width, label in ENTRY_COLUMNS[1:]:
            item = columns_menu.AppendCheckItem(
                wx.ID_ANY, lang.menu_label("view_column_" + key, label))
            self.Bind(wx.EVT_MENU, lambda event, key=key:
                      self.toggle_column("entry_columns", key), item)
            self.column_items[key] = item
        columns_menu.AppendSeparator()
        show_all = columns_menu.Append(wx.ID_ANY, lang.menu_label(
            "show_all_columns",
            "Show &all columns"))
        self.Bind(wx.EVT_MENU, lambda event: self.show_all_columns("entry_columns"),
                  show_all)

        from .authenticator import COLUMNS as AUTH_COLUMNS

        auth_menu = wx.Menu()
        self.auth_column_items = {}
        for key, _heading, _width, label in AUTH_COLUMNS[1:]:
            item = auth_menu.AppendCheckItem(
                wx.ID_ANY, lang.menu_label("auth_view_column_" + key, label))
            self.Bind(wx.EVT_MENU, lambda event, key=key:
                      self.toggle_column("authenticator_columns", key), item)
            self.auth_column_items[key] = item
        auth_menu.AppendSeparator()
        show_all = auth_menu.Append(wx.ID_ANY, lang.menu_label(
            "show_all_columns",
            "Show &all columns"))
        self.Bind(wx.EVT_MENU,
                  lambda event: self.show_all_columns("authenticator_columns"),
                  show_all)

        view_menu = wx.Menu()
        view_menu.AppendSubMenu(sort_menu, lang.menu_label(
            "sort_entries_by",
            "&Sort entries by"))
        view_menu.AppendSubMenu(columns_menu, lang.menu_label(
            "columns_in_the_entry_list",
            "&Columns in the entry list"))
        view_menu.AppendSubMenu(auth_menu, lang.menu_label(
            "columns_in_the_authenticator_list",
            "Columns in the &Authenticator list"))
        self.update_view_menu()
        return view_menu

    def update_view_menu(self):
        """Tick the View menu items that match the settings."""
        column = self.sort_column()
        for key, item in self.sort_items.items():
            item.Check(key == column)
        descending = bool(self.settings.get("sort_descending"))
        self.descending_item.Check(descending)
        self.ascending_item.Check(not descending)
        shown = self.visible_columns("entry_columns")
        for key, item in self.column_items.items():
            item.Check(key in shown)
        shown = self.visible_columns("authenticator_columns")
        for key, item in self.auth_column_items.items():
            item.Check(key in shown)

    def sort_column(self):
        column = self.settings.get("sort_column") or "title"
        return column if column in SORT_COLUMNS else "title"

    def visible_columns(self, setting):
        """The column keys a list shows, in their fixed order, first one included."""
        from .authenticator import COLUMNS as AUTH_COLUMNS

        known = ENTRY_COLUMNS if setting == "entry_columns" else AUTH_COLUMNS
        chosen = self.settings.get(setting)
        if not isinstance(chosen, list):
            chosen = [key for key, *_rest in known[1:]]
        return [known[0][0]] + [key for key, *_rest in known[1:] if key in chosen]

    def set_sort(self, column=None, descending=None):
        if column is not None:
            self.settings["sort_column"] = column
        if descending is not None:
            self.settings["sort_descending"] = bool(descending)
        self.settings.save()
        self.update_view_menu()
        self.refresh_entries()
        order = (lang.t("actions_announcements", "order_descending", "descending")
                 if self.settings.get("sort_descending") else
                 lang.t("actions_announcements", "order_ascending", "ascending"))
        column = self.sort_column()
        self.SetStatus(lang.t(
            "actions_announcements", "sorted_by", "Sorted by {column}, {order}.",
            column=lang.t("actions_announcements", "column_name_" + column,
                          COLUMN_NAMES[column]),
            order=order))

    def toggle_column(self, setting, key):
        shown = self.visible_columns(setting)[1:]
        hiding = key in shown
        self.settings[setting] = ([item for item in shown if item != key] if hiding
                                  else shown + [key])
        self.apply_columns(setting)
        name = lang.t("actions_announcements", "column_name_" + key,
                      COLUMN_NAMES[key])
        if hiding:
            text = lang.t("actions_announcements", "column_hidden",
                          "{column} column hidden.", column=name)
        else:
            text = lang.t("actions_announcements", "column_shown",
                          "{column} column shown.", column=name)
        self.SetStatus(text[:1].upper() + text[1:])

    def show_all_columns(self, setting):
        self.settings[setting] = list(Settings().get(setting))
        self.apply_columns(setting)
        self.SetStatus(lang.t(
            "actions_announcements", "all_columns_shown",
            "All columns shown."))

    def apply_columns(self, setting):
        self.settings.save()
        self.update_view_menu()
        if setting == "entry_columns":
            self.build_entry_columns()
            self.refresh_entries()
        else:
            self.authenticator.build_columns()
            self.authenticator.refresh()

    def build_entry_columns(self):
        """Lay out the entry list's columns from the View menu choices."""
        self.entry_list.ClearAll()
        self.entry_column_keys = self.visible_columns("entry_columns")
        widths = {key: width for key, _heading, width, _label in ENTRY_COLUMNS}
        headings = {key: heading for key, heading, _width, _label in ENTRY_COLUMNS}
        for index, key in enumerate(self.entry_column_keys):
            self.entry_list.InsertColumn(
                index, lang.t("main_ui", "entry_column_" + key, headings[key]),
                width=widths[key])

    def entry_cell(self, key, entry, shown_name):
        if key == "title":
            return shown_name
        if key == "username":
            return entry["username"] or ""
        if key == "site":
            return names.display_site(entry)
        if key == "group":
            return entry.get("group_name") or ""
        if key == "totp":
            return (totp.format_code(totp.current_code(entry))
                    if totp.has_code(entry) else "")
        if key == "modified":
            return time.strftime("%Y-%m-%d",
                                 time.localtime(entry["modified"] or 0))
        return ""

    def sort_entries(self, entries):
        """Sort in place by the View menu choice; empty values go last."""
        column = self.sort_column()
        descending = bool(self.settings.get("sort_descending"))

        # Sort by the name the list shows, so entries named only by a web
        # address sit with the rest instead of all under "h" for https.
        def name(entry):
            return names.display_title(entry).lower()

        if column == "modified":
            entries.sort(key=lambda entry: (entry.get("modified") or 0, name(entry)),
                         reverse=descending)
            return
        value = {
            "title": name,
            "username": lambda entry: (entry.get("username") or "").lower(),
            "site": lambda entry: names.display_site(entry).lower(),
            "group": lambda entry: (entry.get("group_name") or "").lower(),
        }[column]
        filled = [entry for entry in entries if value(entry)]
        empty = [entry for entry in entries if not value(entry)]
        filled.sort(key=lambda entry: (value(entry), name(entry)),
                    reverse=descending)
        empty.sort(key=name)
        entries[:] = filled + empty

    def on_column_click(self, event):
        """A click on a heading sorts by it; a second click reverses."""
        column = event.GetColumn()
        if not 0 <= column < len(self.entry_column_keys):
            return
        key = self.entry_column_keys[column]
        if key not in SORT_COLUMNS:
            return
        if key == self.sort_column():
            self.set_sort(descending=not self.settings.get("sort_descending"))
        else:
            self.set_sort(key, descending=False)

    def _build_layout(self):
        outer = wx.Panel(self)
        self.notebook = wx.Notebook(outer)
        self.notebook.SetName(lang.t(
            "dialogs", "main_sections",
            "Main sections"))

        panel = wx.Panel(self.notebook)
        self.filter_box = wx.SearchCtrl(panel, style=wx.TE_PROCESS_ENTER)
        self.filter_box.SetName(lang.t(
            "dialogs", "search_entries",
            "Search entries"))
        self.filter_box.SetDescriptiveText(lang.t(
            "dialogs", "search_entries",
            "Search entries"))

        self.group_label = wx.StaticText(panel, label=lang.control_label(
            "groups_2",
            "&Groups"))
        self.group_list = wx.ListBox(panel, size=(200, -1))
        self.group_list.SetName(lang.t("dialogs", "groups", "Groups"))

        self.new_group_button = wx.Button(panel, label=lang.control_label(
            "new_group_2",
            "New &group..."))
        self.new_group_button.SetName(lang.t(
            "dialogs", "new_group",
            "New group"))

        self.entry_label = wx.StaticText(panel, label=lang.control_label(
            "entries_2",
            "&Entries"))
        self.entry_list = wx.ListCtrl(panel, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.entry_list.SetName(lang.t("dialogs", "entries", "Entries"))
        self.build_entry_columns()

        self.details = DetailsPane(panel, self)

        top = wx.BoxSizer(wx.HORIZONTAL)
        top.Add(self.filter_box, 1, wx.EXPAND | wx.ALL, 6)

        left = wx.BoxSizer(wx.VERTICAL)
        left.Add(self.group_label, 0, wx.ALL, 4)
        left.Add(self.group_list, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 4)
        left.Add(self.new_group_button, 0, wx.ALL, 4)

        middle = wx.BoxSizer(wx.VERTICAL)
        middle.Add(self.entry_label, 0, wx.ALL, 4)
        middle.Add(self.entry_list, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 4)

        body = wx.BoxSizer(wx.HORIZONTAL)
        body.Add(left, 0, wx.EXPAND | wx.ALL, 4)
        body.Add(middle, 2, wx.EXPAND | wx.ALL, 4)
        body.Add(self.details, 1, wx.EXPAND | wx.ALL, 4)

        self.tab_hint = wx.StaticText(
            panel,
            label=lang.t(
                "dialogs", "two_pages_this_list_of_entries",
                "Two pages: this list of entries, and the Authenticator for "
                "accounts with a verification code. Control 2 opens the "
                "Authenticator page, Control 1 comes back here."))
        self.tab_hint.Wrap(900)
        self.open_2fa_button = wx.Button(
            panel, label=lang.control_label(
                "open_the_authenticator_page_control_2",
                "Open the &Authenticator page, Control 2"))
        self.open_2fa_button.SetName(lang.t(
            "dialogs", "open_the_authenticator_page",
            "Open the Authenticator page"))
        self.open_2fa_button.Bind(
            wx.EVT_BUTTON, lambda event: self.show_authenticator())

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(top, 0, wx.EXPAND)
        root.Add(self.tab_hint, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 6)
        root.Add(self.open_2fa_button, 0, wx.LEFT | wx.BOTTOM, 6)
        root.Add(body, 1, wx.EXPAND)
        panel.SetSizer(root)
        self.panel = panel

        self.notebook.AddPage(panel, lang.control_label(
            "entries_2",
            "&Entries"))
        self.authenticator = AuthenticatorPage(self.notebook, self)
        self.notebook.AddPage(self.authenticator,
                              lang.control_label(
                                  "authenticator_control_2",
                                  "&Authenticator, Control 2"))
        self.notebook.Bind(wx.EVT_NOTEBOOK_PAGE_CHANGED, self.on_page_changed)

        self.banner = theme.Banner(outer, self.banner_subtitle())
        outer_root = wx.BoxSizer(wx.VERTICAL)
        outer_root.Add(self.banner, 0, wx.EXPAND)
        outer_root.Add(self.notebook, 1, wx.EXPAND | wx.TOP, 4)
        outer.SetSizer(outer_root)
        self.outer = outer

    def on_page_changed(self, event):
        if event.GetSelection() == self.notebook.GetPageCount() - 1:
            self.authenticator.refresh()
            self.authenticator.focus_list()
        event.Skip()

    def show_authenticator(self):
        """Switch to the authenticator page and announce the first account."""
        self.notebook.SetSelection(self.notebook.GetPageCount() - 1)
        self.authenticator.refresh()
        self.authenticator.focus_list()

    def _bind_events(self):
        self.group_list.Bind(wx.EVT_LISTBOX, lambda event: self.refresh_entries())
        self.filter_box.Bind(wx.EVT_TEXT, lambda event: self.refresh_entries())
        self.new_group_button.Bind(wx.EVT_BUTTON, self.on_new_group)
        self.entry_list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_entry_selected)
        self.entry_list.Bind(wx.EVT_LIST_ITEM_ACTIVATED,
                             lambda event: self.on_edit_entry(event))
        self.entry_list.Bind(wx.EVT_KEY_DOWN, self.on_entry_list_key)
        self.entry_list.Bind(wx.EVT_LIST_COL_CLICK, self.on_column_click)
        # Applications key, Shift+F10 and right click all open it.
        self.entry_list.Bind(wx.EVT_CONTEXT_MENU, self.on_entry_context_menu)
        self.Bind(wx.EVT_CLOSE, self.on_close)
        self.Bind(wx.EVT_ICONIZE, self.on_iconize)
        self.Bind(wx.EVT_CHAR_HOOK, self.on_char_hook)
        self.Bind(wx.EVT_MENU_OPEN, self.on_menu_open)
        self.details.attach_drop_target()

    # ------------------------------------------------------------------ data

    def refresh_groups(self):
        self.group_list.Clear()
        self.group_list.Append(lang.menu_label("all_entries", "All entries"), None)
        self.group_list.Append(lang.menu_label("favourites", "Favourites"), None)
        for group in self.vault.groups():
            self.group_list.Append(group["name"], group["id"])
        if self.group_list.GetCount():
            self.group_list.SetSelection(0)

    def selected_group(self):
        selection = self.group_list.GetSelection()
        if selection <= 0:
            return "all"
        if selection == 1:
            # The second row is Favourites, which has no group of its own.
            return "favourites"
        return self.group_list.GetClientData(selection)

    def refresh_entries(self, keep_selection=True):
        previous = self.current_entry_id
        self.entry_list.DeleteAllItems()
        group = self.selected_group()
        search = self.filter_box.GetValue().strip()
        self.filtered_entries = self.vault.entries(
            group_id=group if isinstance(group, int) else None,
            search=search,
            favourites_only=(group == "favourites" or
                             (group == "all" and False)),
        )
        if group == "favourites":
            self.filtered_entries = [e for e in self.filtered_entries
                                     if e.get("favourite")]
        self.sort_entries(self.filtered_entries)
        shown = names.display_titles(self.filtered_entries)
        for row, entry in enumerate(self.filtered_entries):
            for column, key in enumerate(self.entry_column_keys):
                text = self.entry_cell(key, entry, shown[row])
                if column == 0:
                    self.entry_list.InsertItem(row, text)
                else:
                    self.entry_list.SetItem(row, column, text)
        index = 0
        if keep_selection and previous:
            for row, entry in enumerate(self.filtered_entries):
                if entry["id"] == previous:
                    index = row
                    break
        if self.filtered_entries:
            self.entry_list.Select(index)
            self.entry_list.Focus(index)
            self.show_entry(self.filtered_entries[index]["id"])
        else:
            self.current_entry_id = None
            self.details.clear()
            self.SetStatus(lang.t(
                "actions_announcements", "no_entries_match",
                "No entries match."), speak=False)
        if hasattr(self, "authenticator"):
            self.authenticator.refresh()
        self.update_status()

    def show_entry(self, entry_id):
        entry = self.vault.get_entry(entry_id)
        if not entry:
            self.details.clear()
            return
        self.current_entry_id = entry_id
        self.details.show(entry)

    def update_status(self):
        summary = self.vault.statistics()
        self.SetStatus(
            lang.t(
                "actions_announcements", "entries_in_groups_with_verification_codes",
                "{entries} entries in {groups} groups. {with_totp} with "
                "verification codes, {with_attachments} with stored files.",
                entries=summary['entries'],
                groups=summary['groups'],
                with_totp=summary['with_totp'],
                with_attachments=summary['with_attachments']),
            speak=False)

    def SetStatus(self, text, speak=True, interrupt=True):
        """Put text on the status bar and say it through the screen reader.

        Screen readers do not read a status bar on their own, so the result
        of an action, such as "Password copied", is also spoken straight away,
        even when it came from a hot key.  speak=False is for summaries that
        refresh by themselves and would only talk over the user.
        """
        if self.GetStatusBar():
            self.GetStatusBar().SetStatusText(text)
        self.last_status = text
        if speak and text and hasattr(self, "banner"):
            self.banner.pulse(text)
        if speak and text and self.IsShown():
            speech.speak(text, interrupt=interrupt, window=self)

    # ------------------------------------------------- window and tray

    def database_name(self):
        return os.path.basename(self.vault.path or "") or "database"

    def banner_subtitle(self):
        kind = (lang.t("dialogs", "keepass_database", "KeePass database") if self.database_name().lower().endswith(".kdbx")
                else lang.t("dialogs", "zkeypass_database", "ZKeypass database"))
        return lang.t(
            "dialogs", "unlocked",
            "Unlocked  ·  {database_name}  ·  {kind}",
            database_name=self.database_name(),
            kind=kind)

    def tray(self):
        return getattr(wx.GetApp(), "tray", None)

    def on_iconize(self, event):
        """Minimised: with the tray icon on, leave the taskbar for the tray."""
        event.Skip()
        if (event.IsIconized() and self.tray() is not None
                and self.settings.get("minimize_to_tray", True)):
            wx.CallAfter(self._hide_to_tray)

    def _hide_to_tray(self):
        if self.IsIconized():
            self.Hide()
            speech.speak(lang.t(
                "actions_announcements", "zkeypass_is_in_the_notification_area",
                "ZKeypass is in the notification area. Windows B reaches it."), interrupt=False, window=self)

    def restore(self):
        """Bring the window back from the tray or the taskbar."""
        if not self.IsShown():
            theme.fade_in(self)
            self.Show()
        if self.IsIconized():
            self.Iconize(False)
        self.Raise()
        self.restart_auto_lock()
        try:
            if self.notebook.GetSelection() == 0:
                self.entry_list.SetFocus()
        except Exception:
            pass

    def on_quit(self, event=None):
        """Control Shift Q: save, close and end ZKeypass, tray icon included."""
        self.close_reason = "quit"
        app = wx.GetApp()
        if hasattr(app, "quit"):
            app.quit()
        else:
            self.Close()

    # --------------------------------------------------------------- handlers

    def on_entry_context_menu(self, event=None):
        """The actions for the selected entry, as a menu at the entry."""
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(self.current_entry_id) or {}
        menu = wx.Menu()
        items = [
            (lang.menu_label(
                "copy_password_ctrl_shift_c_2",
                "&Copy password\tCtrl+Shift+C"), lambda event: self.copy_field("password"),
             bool(entry.get("password"))),
            (lang.menu_label(
                "copy_user_name_ctrl_b",
                "Copy &user name\tCtrl+B"), lambda event: self.copy_field("username"),
             bool(entry.get("username"))),
            (lang.menu_label("show_password", "Show pass&word..."), self.on_show_password,
             bool(entry.get("password"))),
            (lang.menu_label(
                "copy_verification_code_ctrl_t",
                "Copy &verification code\tCtrl+T"), lambda event: self.copy_field("totp"),
             totp.has_code(entry)),
            (lang.menu_label(
                "copy_web_address_ctrl_u",
                "Copy &web address\tCtrl+U"), lambda event: self.copy_field("url"),
             bool(entry.get("url"))),
            (lang.menu_label(
                "open_the_web_address_in_the",
                "&Open the web address in the browser"), self.on_open_url,
             bool(entry.get("url"))),
            None,
            (lang.menu_label("edit_entry_enter_2", "&Edit entry...\tEnter"), self.on_edit_entry, True),
            (lang.menu_label("rename_f2", "Re&name...\tF2"), self.on_rename_entry, True),
            (lang.menu_label("set_the_user_name", "Set the user na&me...") if not entry.get("username")
             else lang.menu_label(
                 "change_the_user_name",
                 "Change the user na&me..."), self.on_set_username, True),
            (lang.menu_label(
                "move_to_another_group",
                "Move to another &group..."), self.on_move_entry, True),
            (lang.menu_label("duplicate", "D&uplicate"), self.on_duplicate_entry, True),
            (lang.menu_label(
                "remove_from_favourites",
                "Remove from &favourites") if entry.get("favourite")
             else lang.menu_label("add_to_favourites", "Add to &favourites"), self.on_toggle_favourite, True),
            (lang.menu_label(
                "auto_type_into_the_last_window",
                "Auto-&type into the last window\tCtrl+Shift+A"),
             self.on_autotype_entry, True),
            None,
            (lang.menu_label("delete_entry_delete", "&Delete entry...\tDelete"), self.on_delete_entry, True),
        ]
        for item in items:
            if item is None:
                menu.AppendSeparator()
                continue
            label, handler, enabled = item
            if not enabled:
                continue  # leave out what this entry has nothing for
            menu_item = menu.Append(wx.ID_ANY, label)
            menu.Bind(wx.EVT_MENU, handler, menu_item)
        self.entry_list.PopupMenu(menu)
        menu.Destroy()

    def on_show_password(self, event=None):
        """Show the password in a read-only box, for reading it aloud."""
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(self.current_entry_id) or {}
        if not entry.get("password"):
            self.SetStatus(lang.t(
                "actions_announcements", "this_entry_has_no_password",
                "This entry has no password."))
            return
        dialog = PasswordDialog(self, names.display_title(entry),
                                entry["password"])
        dialog.ShowModal()
        dialog.Destroy()

    def on_rename_entry(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(self.current_entry_id) or {}
        current = (entry.get("title") or "").strip()
        if names.needs_name(entry):
            current = names.suggest(entry) or current
        dialog = wx.TextEntryDialog(self, lang.t(
            "dialogs", "new_name_for_this_entry",
            "New name for this entry:"),
                                    lang.t(
                                        "dialogs", "rename_entry",
                                        "Rename entry"), current)
        if dialog.ShowModal() == wx.ID_OK and dialog.GetValue().strip():
            self.vault.rename_entry(self.current_entry_id,
                                    dialog.GetValue().strip())
            self.auto_save()
            self.refresh_entries()
            self.SetStatus(lang.t(
                "actions_announcements", "renamed_to",
                "Renamed to {name}.",
                name=dialog.GetValue().strip()))
        dialog.Destroy()

    def on_set_username(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(self.current_entry_id) or {}
        dialog = wx.TextEntryDialog(
            self, lang.t(
                "dialogs", "user_name_or_email_for",
                "User name or email for {display_title}:",
                display_title=names.display_title(entry)),
            lang.t("dialogs", "user_name", "User name"), entry.get("username") or "")
        if dialog.ShowModal() == wx.ID_OK:
            value = dialog.GetValue().strip()
            self.vault.set_username(self.current_entry_id, value)
            self.auto_save()
            self.refresh_entries()
            self.SetStatus(lang.t(
                "actions_announcements", "user_name_saved",
                "User name saved.") if value else
                           lang.t(
                               "actions_announcements", "user_name_cleared",
                               "User name cleared."))
        dialog.Destroy()

    def on_move_entry(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        groups = self.vault.groups()
        if not groups:
            self.SetStatus(lang.t(
                "actions_announcements", "there_are_no_groups_yet_make",
                "There are no groups yet. Make one with New group."))
            return
        dialog = wx.SingleChoiceDialog(
            self, lang.t(
                "dialogs", "move_this_entry_to_which_group",
                "Move this entry to which group?"), lang.t(
                "dialogs", "move_entry",
                "Move entry"),
            [group["name"] for group in groups])
        if dialog.ShowModal() == wx.ID_OK:
            group = groups[dialog.GetSelection()]
            self.vault.move_entry(self.current_entry_id, group["id"])
            self.auto_save()
            self.refresh_entries()
            self.SetStatus(lang.t(
                "actions_announcements", "moved_to",
                "Moved to {name}.",
                name=group['name']))
        dialog.Destroy()

    def on_open_url(self, event=None):
        """Open the entry's web address in the usual browser."""
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        url = ((self.vault.get_entry(self.current_entry_id) or {})
               .get("url") or "").strip()
        if not url:
            self.SetStatus(lang.t(
                "actions_announcements", "this_entry_has_no_web_address",
                "This entry has no web address."))
            return
        if "://" not in url:
            url = "https://" + url
        import webbrowser

        webbrowser.open(url)
        self.SetStatus(lang.t(
            "actions_announcements", "opened_in_the_browser",
            "Opened {url} in the browser.",
            url=names.site_of(url) or url))

    def on_entry_list_key(self, event):
        if event.GetKeyCode() == wx.WXK_DELETE:
            self.on_delete_entry(event)
        else:
            event.Skip()

    def on_entry_selected(self, event):
        row = event.GetIndex()
        if 0 <= row < len(self.filtered_entries):
            self.show_entry(self.filtered_entries[row]["id"])

    def on_char_hook(self, event):
        code = event.GetKeyCode()
        if code == wx.WXK_ESCAPE:
            self.on_close_vault(event)
            return
        if event.ControlDown() and code == ord("1"):
            self.notebook.SetSelection(0)
            self.filter_box.SetFocus()
            # The screen reader names the search box as it takes the focus.
            self.SetStatus(lang.t(
                "actions_announcements", "entries_page",
                "Entries page."), speak=False)
            return
        if event.ControlDown() and code == ord("2"):
            self.show_authenticator()
            return
        if event.ControlDown() and event.ShiftDown() and code == ord("T"):
            self.copy_selected_account_code()
            return
        if event.ControlDown() and code == ord("T"):
            self.copy_field("totp")
            return
        event.Skip()

    def on_new_group(self, event):
        from wx import TextEntryDialog

        dialog = TextEntryDialog(self, lang.t(
            "dialogs", "name_for_the_new_group",
            "Name for the new group:"), lang.t(
            "dialogs", "new_group",
            "New group"))
        if dialog.ShowModal() == wx.ID_OK and dialog.GetValue().strip():
            self.vault.add_group(dialog.GetValue().strip())
            self.auto_save()
            self.refresh_groups()
            self.SetStatus(lang.t(
                "actions_announcements", "group_created",
                "Group {name} created.",
                name=dialog.GetValue().strip()))
        dialog.Destroy()

    def on_new_entry(self, event=None):
        dialog = EntryDialog(self, self.vault, None)
        if dialog.ShowModal() == wx.ID_OK:
            self.auto_save()
            self.refresh_entries(keep_selection=False)
            self.SetStatus(lang.t(
                "actions_announcements", "entry_added",
                "Entry added."))
        dialog.Destroy()

    def on_edit_entry(self, event=None):
        if self.current_entry_id is None:
            return
        dialog = EntryDialog(self, self.vault, self.current_entry_id)
        if dialog.ShowModal() == wx.ID_OK:
            self.auto_save()
            self.refresh_entries()
            self.SetStatus(lang.t(
                "actions_announcements", "entry_saved",
                "Entry saved."))
        dialog.Destroy()

    def on_delete_entry(self, event=None):
        if self.current_entry_id is None:
            return
        entry = self.vault.get_entry(self.current_entry_id)
        if ask_yes_no(self, lang.t(
            "dialogs", "delete_the_entry",
            "Delete the entry \"{title}\"?",
            title=entry["title"])):
            self.vault.delete_entry(self.current_entry_id)
            self.current_entry_id = None
            self.auto_save()
            self.refresh_entries(keep_selection=False)
            self.SetStatus(lang.t(
                "actions_announcements", "entry_deleted",
                "Entry deleted."))

    def on_duplicate_entry(self, event=None):
        if self.current_entry_id is None:
            return
        new_id = self.vault.duplicate_entry(self.current_entry_id)
        self.auto_save()
        self.refresh_entries(keep_selection=False)
        if new_id:
            self.show_entry(new_id)
        self.SetStatus(lang.t(
            "actions_announcements", "entry_duplicated",
            "Entry duplicated."))

    def on_suggest_names(self, event=None):
        """Offer short names for entries named only by a web address."""
        from .dialogs_extras import SuggestNamesDialog

        dialog = SuggestNamesDialog(self, self.vault, self.settings)
        if not dialog.rows:
            dialog.Destroy()
            wx.MessageBox(lang.t(
                "errors", "every_entry_already_has_a_name",
                "Every entry already has a name. Nothing to suggest."),
                          lang.t("dialogs", "suggest_names", "Suggest names"), wx.OK | wx.ICON_INFORMATION, self)
            return
        renamed = dialog.ShowModal() == wx.ID_OK and dialog.renamed
        dialog.state.closed = True
        dialog.state.stop.set()
        dialog.Destroy()
        if renamed:
            self.auto_save()
            self.refresh_entries()
            self.SetStatus(lang.plural(
                "actions_announcements", "renamed_entries", renamed,
                "Renamed {count} entry.", "Renamed {count} entries."))

    def on_toggle_favourite(self, event=None):
        if self.current_entry_id is None:
            return
        entry = self.vault.get_entry(self.current_entry_id)
        was_favourite = bool(entry["favourite"])
        self.vault.set_favourite(self.current_entry_id, not was_favourite)
        self.auto_save()
        self.refresh_entries()
        self.SetStatus(lang.t(
            "actions_announcements", "removed_from_favourites",
            "Removed from favourites.") if was_favourite
                       else lang.t(
                           "actions_announcements", "added_to_favourites",
                           "Added to favourites."))

    def copy_field(self, field):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(self.current_entry_id)
        if field == "totp":
            value = totp.current_code(entry) if totp.has_code(entry) else ""
            if not value:
                self.SetStatus(lang.t(
                    "actions_announcements", "this_entry_has_no_setup_key",
                    "This entry has no setup key."))
                return
            message = lang.t(
                "dialogs", "code_copied",
                "Code {code} copied.",
                code=totp.format_code(value))
        else:
            what = {"username": lang.t("dialogs", "user_name_2", "user name"), "password": "password",
                    "url": lang.t("dialogs", "web_address_2", "web address")}.get(field, field)
            value = entry.get(field) or ""
            if not value:
                self.SetStatus(lang.t(
                    "actions_announcements", "this_entry_has_no_to_copy",
                    "This entry has no {what} to copy.",
                    what=what))
                return
            message = lang.t(
                "dialogs", "copied",
                "{what} copied.",
                what=what.capitalize())
        self.set_clipboard(value)
        self.SetStatus(message + lang.t(
            "actions_announcements", "clipboard_clears_in_seconds",
            " Clipboard clears in {seconds} seconds.",
            seconds=self.settings['clipboard_clear_seconds']))

    def set_clipboard(self, text):
        """Copy a secret, kept out of clipboard history, cleared later."""
        from . import clipboard

        seconds = int(self.settings.get("clipboard_clear_seconds") or 0)
        if not clipboard.copy_secret(text, seconds):
            self.SetStatus(lang.t(
                "actions_announcements", "could_not_open_the_clipboard",
                "Could not open the clipboard."))

    def clear_clipboard(self, event=None):
        from . import clipboard

        clipboard.clear(force=True)
        self.SetStatus(lang.t(
            "actions_announcements", "clipboard_cleared",
            "Clipboard cleared."))

    def on_attach_file(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        from . import filebrowser

        path, _kind = filebrowser.choose_file(
            self, title=lang.t(
                "dialogs", "choose_a_file_to_encrypt_inside",
                "Choose a file to encrypt inside this entry"),
            default_dir=self.settings.get("last_folder") or "",
            wildcard=filebrowser.ANY_WILDCARD)
        if path:
            self.vault.import_file(self.current_entry_id, path)
            self.auto_save()
            self.show_entry(self.current_entry_id)
            self.SetStatus(lang.t(
                "actions_announcements", "stored_file_added_it_is_encrypted",
                "Stored file added. It is encrypted inside the database; the "
                "original file on disk is unchanged."))

    def on_save_attachment(self, event=None):
        attachment_id = self.details.selected_attachment_id()
        if not attachment_id:
            self.SetStatus(lang.t(
                "actions_announcements", "select_a_stored_file_in_the",
                "Select a stored file in the details pane first."))
            return
        self.details.save_attachment(attachment_id)

    def on_totp_tick(self, event):
        """Refresh codes once per second; only the details pane speaks."""
        column = (self.entry_column_keys.index("totp")
                  if "totp" in self.entry_column_keys else -1)
        if column > 0 and self.entry_list.GetItemCount():
            for row, entry in enumerate(self.filtered_entries):
                if not totp.has_code(entry):
                    continue
                code = totp.format_code(totp.current_code(entry))
                if self.entry_list.GetItemText(row, column) != code:
                    self.entry_list.SetItem(row, column, code)
        if self.current_entry_id:
            self.details.refresh_totp()
        if hasattr(self, "authenticator"):
            self.authenticator.tick()

    # -------------------------------------------------------------- new tools

    def register_hotkey(self):
        """Bind the global auto-type hot key, if one is configured."""
        self.unregister_hotkey()
        if not self.settings.get("autotype_enabled"):
            return
        text = (self.settings.get("autotype_hotkey") or "").strip().lower()
        if not text:
            return
        modifiers = 0
        key = ""
        for part in text.replace(" ", "").split("+"):
            if part in ("ctrl", "control"):
                modifiers |= wx.MOD_CONTROL
            elif part == "alt":
                modifiers |= wx.MOD_ALT
            elif part == "shift":
                modifiers |= wx.MOD_SHIFT
            elif part in ("win", "meta", "super"):
                modifiers |= getattr(wx, "MOD_WIN", 0)
            else:
                key = part
        if not key:
            return
        self.hotkey_id = wx.NewIdRef()
        try:
            registered = self.RegisterHotKey(self.hotkey_id, modifiers, key[0])
        except Exception:
            registered = False
        if registered:
            self.Bind(wx.EVT_HOTKEY, self.on_hotkey, id=self.hotkey_id)
            self.SetStatus(lang.t(
                "actions_announcements", "auto_type_hot_key_is_ready",
                "Auto-type hot key {text_value} is ready.",
                text_value=text), speak=False)
        else:
            self.hotkey_id = None
            self.SetStatus(lang.t(
                "actions_announcements", "another_program_already_uses_so_the",
                "Another program already uses {text_value}, so the auto-type "
                "hot key is not available.",
                text_value=text))

    def register_totp_hotkey(self):
        """Bind the global copy-a-code hot key from any other program."""
        self.unregister_totp_hotkey()
        text = (self.settings.get("totp_hotkey") or "").strip().lower()
        if not text or not self.settings.get("totp_hotkey_enabled", True):
            return
        modifiers = 0
        key = ""
        for part in text.replace(" ", "").split("+"):
            if part in ("ctrl", "control"):
                modifiers |= wx.MOD_CONTROL
            elif part == "alt":
                modifiers |= wx.MOD_ALT
            elif part == "shift":
                modifiers |= wx.MOD_SHIFT
            elif part in ("win", "meta", "super"):
                modifiers |= getattr(wx, "MOD_WIN", 0)
            else:
                key = part
        if not key or not key.isalpha():
            self.SetStatus(
                lang.t(
                    "actions_announcements", "the_verification_code_hot_key_must",
                    "The verification code hot key {text_value} must end "
                    "with a letter, for example Control+Alt+T, so it has "
                    "been left off.",
                    text_value=text))
            return
        self.totp_hotkey_id = wx.NewIdRef()
        try:
            registered = self.RegisterHotKey(self.totp_hotkey_id, modifiers,
                                             ord(key[0].upper()))
        except Exception:
            registered = False
        if registered:
            self.Bind(wx.EVT_HOTKEY, self.on_totp_hotkey, id=self.totp_hotkey_id)
        else:
            self.totp_hotkey_id = None
            self.SetStatus(
                lang.t(
                    "actions_announcements", "another_program_already_uses_so_the_2",
                    "Another program already uses {text_value}, so the "
                    "verification code hot key is not available.",
                    text_value=text))

    def unregister_totp_hotkey(self):
        if getattr(self, "totp_hotkey_id", None) is not None:
            try:
                self.UnregisterHotKey(self.totp_hotkey_id)
            except Exception:
                pass
            self.totp_hotkey_id = None

    def on_totp_hotkey(self, event):
        """Copy the code of the account chosen in the authenticator page."""
        self.copy_selected_account_code()

    def on_add_secret(self, event=None):
        """Open the authenticator page of the selected entry's editor."""
        entry_id = self.current_entry_id
        authenticator = getattr(self, "authenticator", None)
        if (authenticator is not None
                and self.notebook.GetSelection() == self.notebook.GetPageCount() - 1):
            entry_id = authenticator.selected_entry_id() or entry_id
        if entry_id is None:
            self.SetStatus(
                lang.t(
                    "actions_announcements", "select_an_entry_first_then_choose",
                    "Select an entry first, then choose Add a setup key."))
            wx.MessageBox(
                lang.t(
                    "errors", "select_the_entry_the_account_belongs",
                    "Select the entry the account belongs to on the Entries "
                    "page or on the Authenticator page, then choose this "
                    "command again. The Authenticator page of the entry "
                    "editor opens, where the setup key can be typed or "
                    "pasted from an otpauth link."),
                lang.t("dialogs", "add_a_setup_key", "Add a setup key"), wx.OK | wx.ICON_INFORMATION, self)
            return
        dialog = EntryDialog(self, self.vault, entry_id)
        dialog.notebook.SetSelection(2)
        if dialog.ShowModal() == wx.ID_OK:
            self.auto_save()
        dialog.Destroy()
        self.refresh_entries()
        if hasattr(self, "authenticator"):
            self.authenticator.refresh()
        self.SetStatus(lang.t(
            "actions_announcements", "authenticator_settings_saved_for_the_selecte",
            "Authenticator settings saved for the selected entry."))

    def copy_selected_account_code(self):
        """Copy the code for the entry selected here or in the authenticator."""
        entry_id = self.current_entry_id
        authenticator = getattr(self, "authenticator", None)
        if (self.notebook.GetSelection() == self.notebook.GetPageCount() - 1
                and authenticator is not None):
            entry_id = authenticator.selected_entry_id() or entry_id
        if entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        entry = self.vault.get_entry(entry_id)
        if not entry:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        code = totp.current_code(entry) if totp.has_code(entry) else ""
        if not code:
            self.SetStatus(
                lang.t(
                    "actions_announcements", "has_no_setup_key",
                    "{title} has no setup key.",
                    title=entry.get('title') or lang.t(
                        "dialogs", "that_entry",
                        "That entry")))
            return
        self.set_clipboard(code)
        left = totp.seconds_remaining_for(entry)
        message = (lang.t(
            "dialogs", "code_copied_for_valid_for_seconds",
            "Code {code} copied for {title}. Valid for {left} seconds. "
            "Clipboard clears in {seconds} seconds.",
            code=totp.format_code(code),
            title=entry.get('title') or lang.t(
                "dialogs", "the_selected_entry",
                "the selected entry"),
            left=left,
            seconds=int(self.settings.get('clipboard_clear_seconds') or 0)))
        self.SetStatus(message)
        if authenticator is not None:
            authenticator.describe(entry)

    def unregister_hotkey(self):
        if self.hotkey_id is not None:
            try:
                self.UnregisterHotKey(self.hotkey_id)
            except Exception:
                pass
            self.hotkey_id = None

    def on_hotkey(self, event):
        self.on_autotype()

    def on_autotype(self, event=None):
        """Pick an entry for the focused window and type it there."""
        dialog = AutoTypeDialog(self, self.vault, self.settings,
                                preset_entry_id=self.current_entry_id)
        dialog.ShowModal()
        dialog.Destroy()
        if dialog.result:
            self.SetStatus(dialog.result)

    def on_autotype_entry(self, event=None):
        """Auto-type the selected entry straight away."""
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        if self.autotype_in_progress:
            return
        record = self.vault.get_entry(self.current_entry_id)
        title = autotype.active_window_title()
        delay = int(self.settings.get("autotype_delay_ms") or 20)
        self.autotype_in_progress = True
        try:
            if self.settings.get("autotype_minimise"):
                self.Iconize(True)
            wx.Yield()
            report = autotype_store.type_entry(self.vault, record, title,
                                               delay_ms=delay)
            self.SetStatus(report)
        except autotype.AutoTypeError as error:
            wx.MessageBox(str(error), "Auto-type", wx.OK | wx.ICON_ERROR, self)
        finally:
            self.autotype_in_progress = False
            if self.settings.get("autotype_minimise"):
                self.Iconize(False)
                self.Raise()

    def on_autotype_settings(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        dialog = AutoTypeEditDialog(self, self.vault, self.current_entry_id)
        dialog.ShowModal()
        saved = dialog.saved
        dialog.Destroy()
        if saved:
            self.auto_save()
            self.SetStatus(lang.t(
                "actions_announcements", "auto_type_settings_saved_for_this",
                "Auto-type settings saved for this entry."))

    def on_passkeys(self, event=None):
        if self.current_entry_id is None:
            self.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_first",
                "Select an entry first."))
            return
        dialog = PasskeysDialog(self, self.vault, self.current_entry_id,
                                self.settings)
        dialog.ShowModal()
        changed = dialog.changed
        dialog.Destroy()
        if changed:
            self.auto_save()
            self.show_entry(self.current_entry_id)
            self.SetStatus(lang.t(
                "actions_announcements", "passkeys_updated",
                "Passkeys updated."))

    def on_browser(self, event=None):
        dialog = BrowserDialog(self, self)
        dialog.ShowModal()
        dialog.Destroy()

    def on_security_key(self, event=None):
        dialog = YubiKeyDialog(self, self.settings)
        dialog.ShowModal()
        dialog.Destroy()

    def on_details(self, event=None):
        """Name the format, the cipher, the key derivation and the lock parts."""
        lines = [lang.t(
            "dialogs", "database_file_2",
            "Database file: {path}",
            path=self.vault.path)]
        is_kdbx = str(self.vault.path or "").lower().endswith(".kdbx")
        lines.append(lang.t("dialogs", "format_2", "Format: ") + (lang.t(
            "dialogs", "keepass_database_kdbx_opens_in_keepassxc",
            "KeePass database (.kdbx), opens in KeePassXC and KeePass too") if is_kdbx else
                                   lang.t(
                                       "dialogs", "zkeypass_database_zkp_opens_in_zkeypass",
                                       "ZKeypass database (.zkp), opens in "
                                       "ZKeypass only")))
        summary = getattr(self.vault, "cryptography_summary", None)
        if summary:
            lines.append(lang.t(
                "dialogs", "encryption_2",
                "Encryption: {summary}",
                summary=summary()))
        else:
            cipher, kdf = self.vault.cryptography()
            from .crypto import CIPHER_LABELS, KDF_LABELS

            lines.append(lang.t(
                "dialogs", "encryption_3",
                "Encryption: {cipher}, {kdf}.",
                cipher=CIPHER_LABELS.get(cipher, cipher),
                kdf=KDF_LABELS.get(kdf, kdf)))
        statistics = self.vault.statistics()
        lines.append(lang.t(
            "dialogs", "entries_in_groups",
            "Entries: {entries} in {groups} groups.",
            entries=statistics['entries'],
            groups=statistics['groups']))
        lines.append(lang.t(
            "dialogs", "with_verification_codes",
            "With verification codes: {with_totp}.",
            with_totp=statistics['with_totp']))
        lines.append(lang.t(
            "dialogs", "with_stored_files",
            "With stored files: {with_attachments}.",
            with_attachments=statistics['with_attachments']))
        settings = self.vault.meta.get("custom_data", {})             if hasattr(self.vault, "meta") else {}
        lines.append(lang.t("dialogs", "locked_with", "Locked with: ") +
                     ", ".join(item for item in (
                         lang.t(
                             "dialogs", "a_master_password",
                             "a master password") if self.password else "",
                         lang.t("dialogs", "a_key_file", "a key file") if getattr(self.password, "keyfile", None)
                         else "",
                         lang.t("dialogs", "a_security_key", "a security key")
                         if getattr(self.password, "challenge_response", None)
                         else "") if item))
        if settings:
            lines.append(lang.t(
                "dialogs", "custom_data_keys",
                "Custom data keys: {count}.",
                count=len(settings)))
        wx.MessageBox("\n".join(lines), lang.t(
            "dialogs", "database_and_encryption_details",
            "Database and encryption details"),
                      wx.OK | wx.ICON_INFORMATION, self)

    # ------------------------------------------------------- browser service

    def start_browser_server(self):
        """Start listening for a browser extension on the loopback address."""
        from . import browser

        if self.browser_server is not None and self.browser_server.running:
            return self.browser_server.port
        try:
            if os.path.isfile(self.vault.path):
                version = self.vault.meta.get("format_version", 0)
                if version:
                    from .kdbx_vault import KdbxVault

                    if isinstance(self.vault, KdbxVault):
                        self.vault.meta.setdefault("public_custom_data", {})[
                            "ZKeypass Browser"] = "enabled"
        except Exception:
            pass
        server = browser.BrowserServer(
            self.vault, self.password,
            port=int(self.settings.get("browser_port") or browser.DEFAULT_PORT),
            ask_permission=self.ask_browser_permission,
            lock_callback=lambda: wx.CallAfter(self.Close))
        server.bridge.totp = totp
        from . import generator

        server.bridge.generator = generator
        server.start()
        self.browser_server = server
        self.browser_bridge = server.bridge
        self.settings["browser_port"] = server.port
        self.settings["browser_enabled"] = True
        self.settings.save()
        self.SetStatus(lang.t(
            "actions_announcements", "browser_integration_listening_on_port",
            "Browser integration listening on port {port}.",
            port=server.port))
        return server.port

    def stop_browser_server(self):
        was_running = self.browser_server is not None
        if was_running:
            self.browser_server.stop()
            self.browser_server = None
        self.browser_bridge = None
        self.settings["browser_enabled"] = False
        self.settings.save()
        self.SetStatus(lang.t(
            "actions_announcements", "browser_integration_stopped",
            "Browser integration stopped."), speak=was_running)

    def ask_browser_permission(self, name):
        """Ask the user before pairing a browser."""
        if not self.settings.get("browser_ask", True):
            return True
        answer = wx.MessageBox(
            lang.t(
                "errors", "is_asking_to_connect_to_zkeypass",
                "{name} is asking to connect to ZKeypass and read logins from "
                "this database. Allow the pairing?",
                name=name), lang.t(
                "dialogs", "browser_integration",
                "Browser integration"),
            wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION, self)
        return answer == wx.YES

    def on_generator(self, event=None):
        dialog = GeneratorDialog(self, self.settings)
        dialog.ShowModal()
        dialog.Destroy()

    def on_report(self, event=None):
        dialog = ReportsDialog(self, self.vault, self.settings)
        dialog.ShowModal()
        dialog.Destroy()

    def on_ssh_keys(self, event=None):
        dialog = SshKeysDialog(self, self.vault, self.ssh_server)
        dialog.ShowModal()
        dialog.Destroy()

    def on_settings(self, event=None):
        dialog = SettingsDialog(self, self.settings)
        if dialog.ShowModal() == wx.ID_OK:
            self.settings.save()
            app = wx.GetApp()
            if hasattr(app, "apply_settings"):
                app.apply_settings(self)
            self.restart_auto_lock()
            self.register_hotkey()
            self.register_totp_hotkey()
            if self.settings.get("browser_enabled") and not (
                    self.browser_server and self.browser_server.running):
                try:
                    self.start_browser_server()
                except Exception as error:
                    wx.MessageBox(str(error), lang.t(
                        "dialogs", "browser_integration",
                        "Browser integration"),
                                  wx.OK | wx.ICON_ERROR, self)
            elif not self.settings.get("browser_enabled"):
                self.stop_browser_server()
        dialog.Destroy()

    def _run_import(self, runner):
        """Run one import dialog, then save, refresh and announce the count.

        runner(parent, vault, start_folder) opens the right chooser, reads the
        file and adds its entries; every import shares the rest.
        """
        before = self.vault.entry_count() if hasattr(self.vault, "entry_count") \
            else len(self.vault.entries())
        runner(self, self.vault,
               self.settings.get("last_folder") or paths.BASE_DIR)
        self.auto_save()
        self.refresh_entries(keep_selection=False)
        after = self.vault.entry_count() if hasattr(self.vault, "entry_count") \
            else len(self.vault.entries())
        if after > before:
            self.SetStatus(lang.t(
                "actions_announcements", "imported_entries",
                "Imported {count} entries. ",
                count=after - before) +
                           self.last_status)

    def on_import_csv(self, event=None):
        """Add the rows of a CSV export, such as a KeePassXC export, to the
        database that is already open."""
        from .importer import import_csv_dialog

        self._run_import(import_csv_dialog)

    def on_import_bitwarden(self, event=None):
        """Add the entries of a Bitwarden JSON export, encrypted or plain."""
        from .importer import import_bitwarden_dialog

        self._run_import(import_bitwarden_dialog)

    def on_import_1pux(self, event=None):
        """Add the entries of a 1Password 1PUX export."""
        from .importer import import_1pux_dialog

        self._run_import(import_1pux_dialog)

    def on_import_keepass1(self, event=None):
        """Add the entries of a KeePass 1.x (.kdb) database."""
        from .importer import import_keepass1_dialog

        self._run_import(import_keepass1_dialog)

    def on_import_pwsafe(self, event=None):
        """Add the entries of a Password Safe v3 (.psafe3) database."""
        from .importer import import_pwsafe_dialog

        self._run_import(import_pwsafe_dialog)

    def on_import_opvault(self, event=None):
        """Add the entries of a 1Password OPVault folder."""
        from .importer import import_opvault_dialog

        self._run_import(import_opvault_dialog)

    def on_import_protonpass(self, event=None):
        """Add the entries of a Proton Pass export (ZIP or JSON)."""
        from .importer import import_protonpass_dialog

        self._run_import(import_protonpass_dialog)

    def on_import_enpass(self, event=None):
        """Add the entries of an Enpass JSON export."""
        from .importer import import_enpass_dialog

        self._run_import(import_enpass_dialog)

    def on_import_dashlane(self, event=None):
        """Add the entries of a Dashlane JSON export."""
        from .importer import import_dashlane_dialog

        self._run_import(import_dashlane_dialog)

    def hotkeys_text(self):
        """Every keyboard shortcut, as plain lines a screen reader reads one by one.

        The menu part is read from the menu bar itself, so it always matches
        the keys that really work.
        """
        lines = [lang.t(
            "help", "hot_keys_that_work_in_every",
            "Hot keys that work in every program, while a database is open")]
        if self.settings.get("totp_hotkey_enabled", True) and \
                self.settings.get("totp_hotkey"):
            lines.append(lang.t(
                "help", "copy_the_code_of_the_account",
                "  {totp_hotkey}: copy the code of the account selected on "
                "the Authenticator page",
                totp_hotkey=self.settings['totp_hotkey']))
        if self.settings.get("autotype_enabled") and \
                self.settings.get("autotype_hotkey"):
            lines.append(lang.t(
                "help", "auto_type_an_entry_into_the",
                "  {autotype_hotkey}: auto-type an entry into the window you "
                "are working in",
                autotype_hotkey=self.settings['autotype_hotkey']))
        lines.append(lang.t(
            "help", "these_two_can_be_changed_in",
            "  These two can be changed in Tools, Settings."))

        lines += ["", lang.t(
            "help", "notification_area_icon",
            "Notification area icon"),
                  lang.t(
                      "help", "windows_b_then_the_arrow_keys",
                      "  Windows+B, then the arrow keys: reach the ZKeypass "
                      "icon"),
                  lang.t(
                      "help", "enter_or_a_click_show_zkeypass",
                      "  Enter or a click: show ZKeypass, or unlock it when "
                      "locked"),
                  lang.t(
                      "help", "applications_key_or_shift_f10_its",
                      "  Applications key or Shift+F10: its menu, with Show "
                      "ZKeypass, Settings and Quit ZKeypass"),
                  lang.t(
                      "help", "minimising_the_window_puts_zkeypass_there",
                      "  Minimising the window puts ZKeypass there; "
                      "Control+Shift+Q quits it completely")]

        lines += ["", lang.t("help", "main_window", "Main window"),
                  lang.t(
                      "help", "control_1_the_entries_page_with",
                      "  Control+1: the Entries page, with the focus in the "
                      "search box"),
                  lang.t(
                      "help", "control_2_the_authenticator_page",
                      "  Control+2: the Authenticator page"),
                  lang.t(
                      "help", "escape_lock_and_close_the_database",
                      "  Escape: lock and close the database"),
                  lang.t(
                      "help", "alt_plus_the_underlined_letter_open",
                      "  Alt plus the underlined letter: open a menu, for "
                      "example Alt+V for View"),
                  "", lang.t("help", "entry_list", "Entry list"),
                  lang.t(
                      "help", "enter_edit_the_selected_entry",
                      "  Enter: edit the selected entry"),
                  lang.t(
                      "help", "f2_rename_the_selected_entry",
                      "  F2: rename the selected entry"),
                  lang.t(
                      "help", "delete_delete_the_selected_entry",
                      "  Delete: delete the selected entry"),
                  lang.t(
                      "help", "applications_key_or_shift_f10_the",
                      "  Applications key or Shift+F10: the actions for the "
                      "selected entry"),
                  lang.t(
                      "help", "clicking_a_column_heading_sorts_by",
                      "  Clicking a column heading sorts by it; clicking it "
                      "again reverses the order"),
                  "", lang.t(
                      "help", "authenticator_list",
                      "Authenticator list"),
                  lang.t(
                      "help", "enter_control_t_or_c_copy",
                      "  Enter, Control+T or C: copy the selected code"),
                  lang.t(
                      "help", "space_read_the_account_and_its",
                      "  Space: read the account and its code aloud"),
                  lang.t(
                      "help", "r_show_the_setup_key",
                      "  R: show the setup key"),
                  lang.t(
                      "help", "s_copy_the_setup_key",
                      "  S: copy the setup key"),
                  lang.t("help", "e_edit_the_entry", "  E: edit the entry"),
                  lang.t(
                      "help", "f5_refresh_the_list",
                      "  F5: refresh the list")]

        bar = self.GetMenuBar()
        for index in range(bar.GetMenuCount()):
            menu_lines = []
            self._menu_hotkeys(bar.GetMenu(index), menu_lines)
            title = bar.GetMenuLabelText(index)
            letter = bar.GetMenuLabel(index).partition("&")[2][:1].upper()
            lines += ["", lang.t(
                "help", "menu_alt",
                "{title} menu, Alt+{letter}",
                title=title,
                letter=letter) if letter else lang.t(
                "help", "menu",
                "{title} menu",
                title=title)]
            lines += menu_lines or [lang.t(
                "help", "no_shortcut_keys_use_the_menu",
                "  No shortcut keys; use the menu.")]

        lines += ["", lang.t(
            "help", "first_window_choose_a_database",
            "First window, choose a database"),
                  lang.t(
                      "help", "enter_on_a_database_in_the",
                      "  Enter on a database in the recent list: open it"),
                  lang.t(
                      "help", "alt_o_open_a_database",
                      "  Alt+O: open a database"),
                  lang.t(
                      "help", "alt_y_keep_a_portable_copy",
                      "  Alt+Y: keep a portable copy"),
                  lang.t(
                      "help", "alt_c_create_a_new_database",
                      "  Alt+C: create a new database"),
                  lang.t(
                      "help", "alt_b_browse_this_computer_for",
                      "  Alt+B: browse this computer for a database file"),
                  lang.t(
                      "help", "alt_q_or_control_shift_q",
                      "  Alt+Q or Control+Shift+Q: quit ZKeypass"),
                  lang.t(
                      "help", "escape_close_the_window_with_the",
                      "  Escape: close the window; with the notification "
                      "area icon on, ZKeypass stays there, locked")]
        return "\n".join(lines)

    def _menu_hotkeys(self, menu, lines, prefix=""):
        for item in menu.GetMenuItems():
            if item.IsSeparator():
                continue
            label = item.GetItemLabel()
            text, _tab, keys = label.partition("\t")
            text = wx.MenuItem.GetLabelText(text).strip().rstrip(".")
            if item.IsSubMenu():
                self._menu_hotkeys(item.GetSubMenu(), lines, f"{prefix}{text}, ")
            elif keys.strip():
                lines.append(f"  {keys.strip()}: {prefix}{text}")

    def on_hotkeys_list(self, event=None):
        dialog = HotkeysDialog(self, self.hotkeys_text())
        dialog.ShowModal()
        dialog.Destroy()

    def on_about(self, event=None):
        from .about_page import show_about
        show_about()

    # ------------------------------------------------------------ vault files

    def auto_save(self):
        try:
            self.vault.save(self.password)
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_save_the_database",
                "Could not save the database: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)

    def on_new_vault(self, event=None):
        from .dialogs import VaultNewDialog

        dialog = VaultNewDialog(self)
        if dialog.ShowModal() != wx.ID_OK:
            dialog.Destroy()
            return
        path, password, keyfile = dialog.result
        options = getattr(dialog, "options", {}) or {}
        dialog.Destroy()
        challenge_response = None
        if options.pop("challenge_response", False):
            from . import yubikey

            try:
                challenge_response = yubikey.challenge_response(
                    b"ZKPass master key", int(self.settings.get("yubikey_slot")
                                              or 1))
            except (yubikey.YubiKeyError, OSError) as error:
                wx.MessageBox(lang.t(
                    "errors", "the_security_key_did_not_answer",
                    "The security key did not answer: {error}",
                    error=error),
                              "ZKeypass", wx.OK | wx.ICON_ERROR, self)
                return
        options.pop("summary", None)
        try:
            from .kdbx_vault import create_any
            from .vault import PasswordPair

            new_vault = create_any(path, password, keyfile,
                                   challenge_response, **options)
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_create_the_database",
                "Could not create the database: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        if challenge_response and path.lower().endswith(".kdbx"):
            new_vault.meta.setdefault("public_custom_data", {})[
                "ZKeypass YubiKey"] = str(int(self.settings.get("yubikey_slot")
                                            or 1))
        pair = PasswordPair(password, keyfile)
        pair.challenge_response = challenge_response
        self.switch_vault(new_vault, pair)

    def on_menu_open(self, event):
        """Rebuild the Recent databases submenu just before it is shown."""
        menu = getattr(self, "recent_menu", None)
        if menu is not None:
            while menu.GetMenuItemCount():
                item = menu.FindItemByPosition(0)
                menu.DestroyItem(item)
            recent = [item for item in (self.settings.get("recent_vaults") or [])
                      if os.path.isfile(item)]
            last = self.settings.get("last_vault") or ""
            if last and os.path.isfile(last) and last not in recent:
                recent.insert(0, last)
            if not recent:
                item = menu.Append(wx.ID_ANY, lang.menu_label(
                    "no_databases_used_yet",
                    "No databases used yet"))
                item.Enable(False)
            for path in recent[:8]:
                item = menu.Append(wx.ID_ANY, path.replace("&", "&&"))
                self.Bind(wx.EVT_MENU, self.recent_handler(path), item)
        event.Skip()

    def recent_handler(self, path):
        return lambda event: self.open_path(path)

    def ask_for_database(self, caption=None):
        """The program's own browser: every drive, every folder, by keyboard.

        Returns a chosen path, or an empty string when the user cancels.
        """
        if caption is None:
            caption = lang.t("dialogs", "open_a_database", "Open a database")
        from . import filebrowser

        path = filebrowser.ask_for_database(self, self.settings, title=caption)
        if path:
            filebrowser.remember_recent_folder(
                self.settings, os.path.dirname(path))
            self.settings.save()
        return path

    def on_browse_database(self, event=None):
        """Kept for older callers: the same as Open database."""
        self.on_open_vault(event)

    def on_open_vault(self, event=None):
        path = self.ask_for_database()
        if path:
            self.open_path(path)

    def on_open_copy(self, event=None):
        """Bring a database into the program folder, then open the copy."""
        from .app import portable_copy

        path = self.ask_for_database(
            lang.t(
                "dialogs", "choose_a_database_to_copy_into_2",
                "Choose a database to copy into the program folder"))
        if not path:
            return
        try:
            copied = portable_copy(path, settings=self.settings)
        except OSError as error:
            wx.MessageBox(lang.t(
                "errors", "the_copy_could_not_be_made",
                "The copy could not be made: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        wx.MessageBox(
            lang.t(
                "errors", "a_copy_is_now_at_the",
                "A copy is now at\n\n{copied}\n\nThe original is unchanged.",
                copied=copied),
            "ZKeypass", wx.OK | wx.ICON_INFORMATION, self)
        self.open_path(copied)

    def open_path(self, path):
        """Open one named database file, asking for its password."""
        from .dialogs import UnlockDialog

        if not os.path.isfile(path):
            wx.MessageBox(lang.t(
                "errors", "is_no_longer_there_2",
                "{path} is no longer there.",
                path=path), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            recent = [item for item in (self.settings.get("recent_vaults") or [])
                      if os.path.isfile(item)]
            self.settings["recent_vaults"] = recent
            self.settings.save()
            return
        from .quick_unlock import unlock_loop

        new_vault, pair = unlock_loop(self, path, UnlockDialog, tries=1)
        if new_vault is None:
            return
        remember_recent(self.settings, path)
        remember_folder(self.settings, path)
        self.settings.save()
        self.switch_vault(new_vault, pair)

    def switch_vault(self, new_vault, password):
        self.stop_ssh_agent()
        self.stop_browser_server()
        try:
            self.vault.save(self.password)
        except Exception:
            pass
        self.vault.close()
        self.vault = new_vault
        self.password = password
        self.current_entry_id = None
        self.details.clear()
        self.filter_box.SetValue("")
        self.refresh_groups()
        self.refresh_entries(keep_selection=False)
        self.SetTitle(lang.t(
            "dialogs", "zkeypass",
            "ZKeypass - {database_name}",
            database_name=self.database_name()))
        self.banner.set_subtitle(self.banner_subtitle())
        if self.tray() is not None:
            self.tray().set_locked(False, self.database_name())
        remember_recent(self.settings, new_vault.path or "")
        remember_folder(self.settings, new_vault.path or "")
        self.settings.save()

    def on_windows_hello(self, event=None):
        """Turn Windows Hello on or off for the open database."""
        from . import quick_unlock, winhello

        path = getattr(self.vault, "path", "") or ""
        if winhello.is_set_up(path):
            if ask_yes_no(self, lang.t(
                "dialogs", "windows_hello_opens_this_database_on",
                "Windows Hello opens this database on this computer. Turn it "
                "off? The master password will be asked next time."), lang.t(
                                    "dialogs", "windows_hello",
                                    "Windows Hello")):
                winhello.forget(path)
                winhello.set_declined(path, False)
                self.SetStatus(lang.t(
                    "actions_announcements", "windows_hello_is_off_for_this",
                    "Windows Hello is off for this database."))
            return
        if getattr(self.password, "challenge_response", None):
            wx.MessageBox(lang.t(
                "errors", "this_database_also_needs_your_security",
                "This database also needs your security key, so it always "
                "asks for it and the master password. Windows Hello is not "
                "used for it."), lang.t(
                              "dialogs", "windows_hello",
                              "Windows Hello"),
                          wx.OK | wx.ICON_INFORMATION, self)
            return
        ready, why = winhello.available()
        if not ready:
            wx.MessageBox(why, lang.t(
                "dialogs", "windows_hello",
                "Windows Hello"), wx.OK | wx.ICON_INFORMATION,
                          self)
            return
        if quick_unlock.turn_on(self, path, str(self.password or ""),
                                getattr(self.password, "keyfile", None)):
            self.SetStatus(lang.t(
                "actions_announcements", "windows_hello_is_on_for_this",
                "Windows Hello is on for this database."))

    def on_save_vault(self, event=None):
        self.auto_save()
        self.SetStatus(lang.t(
            "actions_announcements", "database_saved",
            "Database saved."))

    # ------------------------------------------------------ other formats

    def on_save_as(self, event=None):
        """Copy the open database into a file of the other format."""
        from .convert import save_as

        current = getattr(self.vault, "path", "") or ""
        suggest = "zkp" if current.lower().endswith(".kdbx") else "kdbx"
        dialog = SaveAsDialog(self, current, suggest)
        if dialog.ShowModal() != wx.ID_OK:
            dialog.Destroy()
            return
        choice = dict(dialog.result or {})
        dialog.Destroy()
        if not choice:
            return
        current = os.path.abspath(getattr(self.vault, "path", "") or "")
        if current and os.path.abspath(choice["path"]) == current:
            wx.MessageBox(
                lang.t(
                    "errors", "that_is_the_file_already_open",
                    "That is the file already open. Choose a different name, "
                    "or use Save database to write it in place."), "ZKeypass",
                wx.OK | wx.ICON_WARNING, self)
            return
        self.auto_save()
        try:
            new_vault, counts = save_as(
                self.vault, choice["path"], choice["password"],
                choice["keyfile"], getattr(self.password, "challenge_response", None),
                kind=choice["kind"], options=choice["options"],
                include_attachments=choice.get("attachments", True))
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "the_copy_could_not_be_written",
                "The copy could not be written: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        new_vault.close()
        summary = (lang.t(
            "dialogs", "saved_entries_groups_extra_fields_stored",
            "Saved {entries} entries, {groups} groups, {attributes} extra "
            "fields, {attachments} stored files.",
            entries=counts['entries'],
            groups=counts['groups'],
            attributes=counts['attributes'],
            attachments=counts['attachments']))
        if ask_yes_no(
                self, lang.t(
                    "dialogs", "open_the_new_copy_now_and",
                    "{summary}\n\n{path}\n\nOpen the new copy now and leave "
                    "the original file? The original is not changed either "
                    "way.",
                    summary=summary,
                    path=choice['path'])):
            from .vault import PasswordPair
            from .kdbx_vault import open_any

            pair = PasswordPair(choice["password"], choice["keyfile"])
            pair.challenge_response = getattr(self.password,
                                              "challenge_response", None)
            try:
                opened = open_any(choice["path"], choice["password"],
                                  choice["keyfile"],
                                  getattr(pair, "challenge_response", None))
            except Exception as error:
                wx.MessageBox(lang.t(
                    "errors", "the_copy_was_written_but_could",
                    "The copy was written but could not be reopened: {error}",
                    error=error), "ZKeypass", wx.OK | wx.ICON_ERROR, self)
                return
            self.switch_vault(opened, pair)
            self.SetStatus(lang.t(
                "actions_announcements", "opened_the_new_copy",
                "Opened the new copy: {path}",
                path=choice['path']))
            return
        self.SetStatus(lang.t(
            "actions_announcements", "saved_a_copy_to",
            "Saved a copy to {path}. {summary}",
            path=choice['path'],
            summary=summary))

    def on_export_vault(self, event=None):
        """Write the entries out as CSV, XML, HTML or plain text."""
        from .convert import export_vault

        dialog = ExportDialog(self, self.vault, getattr(self.vault, "path", "") or "")
        if dialog.ShowModal() != wx.ID_OK:
            dialog.Destroy()
            return
        choice = dict(dialog.result or {})
        dialog.Destroy()
        if not choice:
            return
        self.auto_save()
        try:
            report = export_vault(self.vault, choice["path"], choice["kind"],
                                  choice["passwords"],
                                  choice["attachments_folder"])
        except Exception as error:
            wx.MessageBox(lang.t(
                "errors", "the_export_failed",
                "The export failed: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        written = len(report.get("attachments") or [])
        extra = lang.t(
            "dialogs", "and_stored_files",
            " and {count} stored files",
            count=written) if written else ""
        wx.MessageBox(
            lang.t(
                "errors", "exported_entries_to_the_export_is",
                "Exported {entries} entries{extra} to\n\n{path}\n\nThe "
                "export is not encrypted. Delete it when you are finished.",
                entries=report['entries'],
                extra=extra,
                path=report['path']),
            lang.t("dialogs", "export_complete", "Export complete"), wx.OK | wx.ICON_INFORMATION, self)
        self.SetStatus(lang.t(
            "actions_announcements", "exported_entries_to",
            "Exported {entries} entries to {path}",
            entries=report['entries'],
            path=report['path']))

    def on_close_vault(self, event=None):
        if ask_yes_no(self, lang.t(
            "dialogs", "close_the_database_and_return_to",
            "Close the database and return to the unlock screen?")):
            self.close_reason = "lock"
            self.Close()

    def stop_ssh_agent(self):
        if self.ssh_server.running:
            self.ssh_server.stop()

    def restart_auto_lock(self):
        if self.lock_timer:
            self.lock_timer.Stop()
            self.lock_timer = None
        minutes = int(self.settings.get("auto_lock_minutes") or 0)
        if minutes > 0:
            self.lock_timer = wx.Timer(self)
            self.Bind(wx.EVT_TIMER, self.on_auto_lock, self.lock_timer)
            self.lock_timer.Start(minutes * 60 * 1000, oneShot=True)

    def on_auto_lock(self, event=None):
        self.auto_save()
        self.SetStatus(lang.t(
            "actions_announcements", "database_locked_automatically",
            "Database locked automatically."))
        self.close_reason = "autolock"
        self.Close()

    def on_close(self, event):
        from . import clipboard

        # A password copied a moment ago must not outlive the program.
        clipboard.clear(force=False)
        self.totp_timer.Stop()
        # ZKeypass now keeps running after the window closes, so no timer may
        # outlive it.
        if self.lock_timer:
            self.lock_timer.Stop()
            self.lock_timer = None
        self.stop_ssh_agent()
        self.stop_browser_server()
        self.unregister_hotkey()
        self.unregister_totp_hotkey()
        self.settings["window_size"] = list(self.GetSize())
        self.settings.save()
        try:
            self.vault.save(self.password)
        except Exception:
            pass
        event.Skip()
        app = wx.GetApp()
        if hasattr(app, "on_main_closed"):
            wx.CallAfter(app.on_main_closed, self.close_reason)


class PasswordDialog(wx.Dialog):
    """A password shown in plain text, read-only, so it can be read aloud.

    The box has the focus, so the screen reader reads it at once, and the
    arrow keys spell it out character by character.  Nothing is copied.
    """

    def __init__(self, parent, name, password):
        super().__init__(parent, title=lang.t(
            "dialogs", "password_for",
            "Password for {name}",
            name=name))
        label = wx.StaticText(self, label=lang.control_label(
            "password_2",
            "&Password"))
        box = ReadOnlyField(self, value=password, size=(380, -1),
                            style=wx.TE_READONLY)
        box.SetName(lang.t("dialogs", "password", "Password"))
        hint = wx.StaticText(self, label=lang.t(
            "dialogs", "use_the_arrow_keys_to_read",
            "Use the arrow keys to read it one character at a time."))
        copy = wx.Button(self, label=lang.control_label("copy", "&Copy"))
        close = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close_2",
            "Clo&se"))
        copy.Bind(wx.EVT_BUTTON, lambda event: (
            parent.set_clipboard(password),
            parent.SetStatus(lang.t(
                "actions_announcements", "password_copied",
                "Password copied."))))
        buttons = wx.BoxSizer(wx.HORIZONTAL)
        buttons.Add(copy, 0, wx.RIGHT, 6)
        buttons.Add(close, 0)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(label, 0, wx.LEFT | wx.TOP | wx.RIGHT, 12)
        root.Add(box, 0, wx.EXPAND | wx.ALL, 12)
        root.Add(hint, 0, wx.LEFT | wx.RIGHT, 12)
        root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizerAndFit(root)
        box.SetFocus()
        box.SetInsertionPoint(0)


class HotkeysDialog(wx.Dialog):
    """Help, Hotkeys list: every shortcut in a read-only box.

    The box has the focus, so the arrow keys read it line by line, and
    Control+Home and Control+End reach the ends.
    """

    def __init__(self, parent, text):
        super().__init__(parent, title=lang.t(
            "dialogs", "hotkeys_list",
            "Hotkeys list"),
                         style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        label = wx.StaticText(self, label=lang.control_label(
            "hotkeys_2",
            "&Hotkeys"))
        box = wx.TextCtrl(self, value=text, size=(640, 440),
                          style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_DONTWRAP)
        box.SetName(lang.t("dialogs", "hotkeys", "Hotkeys"))
        close = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close_2",
            "Clo&se"))
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(label, 0, wx.LEFT | wx.TOP | wx.RIGHT, 12)
        root.Add(box, 1, wx.EXPAND | wx.ALL, 12)
        root.Add(close, 0, wx.ALIGN_RIGHT | wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        self.SetSizerAndFit(root)
        self.box = box
        box.SetFocus()
        box.SetInsertionPoint(0)


class DetailsPane(wx.Panel):
    """Read-only view of the selected entry, plus stored file handling."""

    def __init__(self, parent, frame):
        super().__init__(parent)
        self.frame = frame
        self.entry = None
        self.fields = {}

        grid = wx.FlexGridSizer(cols=2, vgap=6, hgap=8)
        grid.AddGrowableCol(1, 1)
        labels = [("title", lang.t("dialogs", "title", "Title")), ("username", lang.t(
            "dialogs", "username",
            "Username")),
                  ("password", lang.t("dialogs", "password", "Password")), ("url", lang.t(
                      "dialogs", "web_address",
                      "Web address")),
                  ("group_name", lang.t("dialogs", "group", "Group")), ("notes", lang.t(
                      "dialogs", "notes",
                      "Notes"))]
        for key, caption in labels:
            label = wx.StaticText(self, label=caption)
            style = wx.TE_READONLY
            if key == "password":
                style |= wx.TE_PASSWORD
            if key == "notes":
                control = ReadOnlyField(self, style=style | wx.TE_MULTILINE,
                                        size=(-1, 80))
            else:
                control = ReadOnlyField(self, style=style)
            control.SetName(caption)
            self.fields[key] = control
            grid.Add(label, 0, wx.ALIGN_CENTER_VERTICAL)
            grid.Add(control, 1, wx.EXPAND)

        totp_label = wx.StaticText(self, label=lang.t(
            "dialogs", "verification_code",
            "Verification code"))
        self.totp_field = ReadOnlyField(self, style=wx.TE_READONLY)
        self.totp_field.SetName(lang.t(
            "dialogs", "verification_code",
            "Verification code"))
        self.totp_field.SetToolTip(lang.t(
            "dialogs", "press_control_t_to_copy_this",
            "Press Control T to copy this code."))
        grid.Add(totp_label, 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.totp_field, 1, wx.EXPAND)

        self.attribute_label = wx.StaticText(self, label=lang.t(
            "dialogs", "extra_fields",
            "Extra fields"))
        self.attribute_list = wx.ListBox(self, size=(-1, 70))
        self.attribute_list.SetName(lang.t(
            "dialogs", "extra_fields",
            "Extra fields"))

        self.passkey_label = wx.StaticText(self, label=lang.t(
            "dialogs", "passkeys",
            "Passkeys"))
        self.passkey_list = wx.ListBox(self, size=(-1, 60))
        self.passkey_list.SetName(lang.t("dialogs", "passkeys", "Passkeys"))

        self.attachment_label = wx.StaticText(self, label=lang.t(
            "dialogs", "stored_files",
            "Stored files"))
        self.attachment_list = wx.ListBox(self, size=(-1, 70))
        self.attachment_list.SetName(lang.t(
            "dialogs", "stored_files",
            "Stored files"))
        button_row = wx.BoxSizer(wx.HORIZONTAL)
        for label, handler in ((lang.menu_label("add_a_file", "&Add a file..."), frame.on_attach_file),
                               (lang.menu_label("save_as", "&Save as..."), self.on_save),
                               (lang.menu_label("delete", "&Delete"), self.on_delete)):
            button = wx.Button(self, label=label)
            button.SetName(label.replace("&", "").replace("...", ""))
            button.Bind(wx.EVT_BUTTON, handler)
            button_row.Add(button, 0, wx.RIGHT, 4)

        tool_row = wx.BoxSizer(wx.HORIZONTAL)
        for label, handler in ((lang.menu_label("auto_type", "Auto-&type"), frame.on_autotype_entry),
                               (lang.menu_label(
                                   "auto_type_settings",
                                   "Auto-type &settings"), frame.on_autotype_settings),
                               (lang.menu_label("passkeys", "Pass&keys..."), frame.on_passkeys)):
            button = wx.Button(self, label=label)
            button.SetName(label.replace("&", "").replace("...", ""))
            button.Bind(wx.EVT_BUTTON, handler)
            tool_row.Add(button, 0, wx.RIGHT, 4)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 4)
        root.Add(self.attribute_label, 0, wx.LEFT | wx.TOP, 6)
        root.Add(self.attribute_list, 1, wx.EXPAND | wx.ALL, 4)
        root.Add(self.passkey_label, 0, wx.LEFT | wx.TOP, 6)
        root.Add(self.passkey_list, 1, wx.EXPAND | wx.ALL, 4)
        root.Add(self.attachment_label, 0, wx.LEFT | wx.TOP, 6)
        root.Add(self.attachment_list, 1, wx.EXPAND | wx.ALL, 4)
        root.Add(button_row, 0, wx.ALL, 4)
        root.Add(tool_row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 4)
        self.SetSizer(root)

    def clear(self):
        self.entry = None
        for control in self.fields.values():
            control.SetValue("")
        self.totp_field.SetValue("")
        self.attribute_list.Clear()
        self.passkey_list.Clear()
        self.attachment_list.Clear()

    def show(self, entry):
        self.entry = entry
        for key, control in self.fields.items():
            control.SetValue(str(entry.get(key) or ""))
        self.refresh_totp()
        self.attribute_list.Clear()
        for attribute in self.frame.vault.attributes(entry["id"]):
            value = (lang.t("main_ui", "hidden_value", "hidden")
                     if attribute["hidden"] else attribute["value"])
            self.attribute_list.Append(f"{attribute['name']}: {value}",
                                       attribute["id"])
        self.passkey_list.Clear()
        try:
            from . import passkeys

            for line in passkeys.describe_passkeys(self.frame.vault, entry["id"]):
                self.passkey_list.Append(line)
        except Exception:
            pass
        self.attachment_list.Clear()
        self.attachments = self.frame.vault.attachments(entry["id"])
        for attachment in self.attachments:
            self.attachment_list.Append(
                lang.t(
                    "menus", "bytes",
                    "{name} ({size} bytes)",
                    name=attachment['name'],
                    size=attachment['size']),
                attachment["id"])

    def refresh_totp(self):
        if not self.entry:
            return
        code = (totp.current_code(self.entry) if totp.has_code(self.entry)
                else "")
        if not code:
            if self.totp_field.GetValue():
                self.totp_field.SetValue("")
                self.last_code = ""
            return
        text = f"{totp.format_code(code)}"
        if self.totp_field.GetValue() != text:
            self.totp_field.SetValue(text)

    def selected_attachment_id(self):
        index = self.attachment_list.GetSelection()
        if index < 0:
            return None
        return self.attachment_list.GetClientData(index)

    def on_save(self, event=None):
        attachment_id = self.selected_attachment_id()
        if not attachment_id:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_a_stored_file_first",
                "Select a stored file first."))
            return
        self.save_attachment(attachment_id)

    def save_attachment(self, attachment_id):
        from . import filebrowser

        os.makedirs(paths.EXPORT_DIR, exist_ok=True)
        default_name = ""
        for attachment in self.attachments:
            if attachment["id"] == attachment_id:
                default_name = attachment["name"]
        target, _kind = filebrowser.choose_file(
            self, title=lang.t(
                "dialogs", "save_stored_file",
                "Save stored file"), default_dir=paths.EXPORT_DIR,
            default_name=default_name, wildcard=filebrowser.ANY_WILDCARD,
            save=True)
        if not target:
            return
        try:
            with open(target, "wb") as handle:
                handle.write(self.frame.vault.attachment_data(attachment_id)
                             or b"")
        except OSError as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_save_the_stored_file",
                "Could not save the stored file: {error}",
                error=error), "ZKeypass",
                          wx.OK | wx.ICON_ERROR, self)
            return
        self.frame.SetStatus(lang.t(
            "actions_announcements", "stored_file_saved_to_that_copy",
            "Stored file saved to {target}. That copy is not encrypted; "
            "delete it when you no longer need it.",
            target=target))

    def on_delete(self, event=None):
        attachment_id = self.selected_attachment_id()
        if not attachment_id:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_a_stored_file_first",
                "Select a stored file first."))
            return
        if ask_yes_no(self, lang.t(
            "dialogs", "delete_the_selected_stored_file",
            "Delete the selected stored file?")):
            self.frame.vault.delete_attachment(attachment_id)
            self.frame.auto_save()
            if self.frame.current_entry_id:
                self.show(self.frame.vault.get_entry(self.frame.current_entry_id))
            self.frame.SetStatus(lang.t(
                "actions_announcements", "stored_file_deleted",
                "Stored file deleted."))

    def attach_drop_target(self):
        self.SetDropTarget(FileDropTarget(self.frame))


class FileDropTarget(wx.FileDropTarget):
    """Treat a group of dropped files as plain text and store each one."""

    def __init__(self, frame):
        super().__init__()
        self.frame = frame

    def OnDropFiles(self, x, y, filenames):
        if self.frame.current_entry_id is None:
            self.frame.SetStatus(lang.t(
                "actions_announcements", "select_an_entry_before_dropping_files",
                "Select an entry before dropping files."))
            return False
        for filename in filenames:
            self.frame.vault.import_file(self.frame.current_entry_id, filename)
        self.frame.auto_save()
        self.frame.show_entry(self.frame.current_entry_id)
        self.frame.SetStatus(lang.plural(
            "actions_announcements", "added_stored_files", len(filenames),
            "Added {count} stored file.", "Added {count} stored files."))
        return True
