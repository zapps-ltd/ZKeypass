"""Dialogs for auto-type, browser pairing and passkeys.

Same house rules as dialogs.py: only ordinary wx widgets, every control named
for screen readers, and every action reachable from the keyboard.  The file
is separate so that the main dialog module stays a manageable size.
"""

import os

import wx

from . import (autotype, autotype_store, browser, generator, names, passkeys,
               paths, totp)
from .dialogs import ReadOnlyField, name_for_screen_readers
from .settings import Settings
from . import lang

PRESET_SEQUENCES = (
    ("Username, Tab, Password, Enter", "{USERNAME}{TAB}{PASSWORD}{ENTER}"),
    ("Username, Tab, Password", "{USERNAME}{TAB}{PASSWORD}"),
    ("Username, Tab, Password, Tab, Enter", "{USERNAME}{TAB}{PASSWORD}{TAB}{ENTER}"),
    ("Password only, Enter", "{PASSWORD}{ENTER}"),
    ("Username only, Tab", "{USERNAME}{TAB}"),
    ("Verification code only", "{TOTP}{ENTER}"),
    ("Username, Tab, Password, Delay, Enter",
     "{USERNAME}{TAB}{PASSWORD}{DELAY 500}{ENTER}"),
    ("Select all, Username, Tab, Password, Enter",
     "{CLEARFIELD}{USERNAME}{TAB}{PASSWORD}{ENTER}"),
)

WINDOW_SUGGESTIONS = ("*Chrome*", "*Firefox*", "*Edge*", "*Brave*", "*Opera*",
                      "*Vivaldi*", "*Notepad*", "*Terminal*", "*PuTTY*")


class AutoTypeDialog(wx.Dialog):
    """Choose an entry and type it into whichever window has the focus."""

    def __init__(self, parent, vault, settings=None, preset_entry_id=None):
        super().__init__(parent, title="Auto-type", size=(640, 520))
        self.vault = vault
        self.settings = settings or Settings.load()
        self.records = []
        self.result = ""
        self.exit_code = wx.ID_CANCEL

        self.window_field = wx.TextCtrl(self)
        self.window_field.SetName(lang.t(
            "dialogs", "target_window_title",
            "Target window title"))
        refresh = wx.Button(self, label=lang.control_label(
            "read_active_window",
            "&Read active window"))
        refresh.Bind(wx.EVT_BUTTON, self.on_read_active)
        read_row = wx.BoxSizer(wx.HORIZONTAL)
        read_row.Add(self.window_field, 1, wx.EXPAND | wx.RIGHT, 6)
        read_row.Add(refresh, 0)

        self.filter_box = wx.SearchCtrl(self, style=wx.TE_PROCESS_ENTER)
        self.filter_box.SetName(lang.t(
            "dialogs", "filter_entries",
            "Filter entries"))
        self.filter_box.SetDescriptiveText(lang.t(
            "dialogs", "filter_entries",
            "Filter entries"))
        self.filter_box.Bind(wx.EVT_TEXT, lambda event: self.refresh())

        self.entry_list = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.entry_list.SetName(lang.t(
            "dialogs", "entries_available_for_auto_type",
            "Entries available for auto-type"))
        for index, (heading, width) in enumerate(((lang.t(
            "dialogs", "title",
            "Title"), 200), (lang.t(
            "dialogs", "username",
            "Username"), 150),
                                                  (lang.t(
                                                      "dialogs", "web_address",
                                                      "Web address"), 200))):
            self.entry_list.InsertColumn(index, heading, width=width)
        self.entry_list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_selected)
        self.entry_list.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.on_type)

        self.sequence_field = wx.TextCtrl(self)
        self.sequence_field.SetName(lang.t("dialogs", "sequence", "Sequence"))
        self.sequence_choice = wx.Choice(self, choices=[
            lang.sequence_name(name) for name, _value in PRESET_SEQUENCES])
        self.sequence_choice.SetName(lang.t(
            "dialogs", "common_sequences",
            "Common sequences"))
        self.sequence_choice.Bind(wx.EVT_CHOICE, self.on_preset)
        self.preview = ReadOnlyField(self, style=wx.TE_READONLY)
        self.preview.SetName(lang.t(
            "dialogs", "what_will_be_typed",
            "What will be typed"))
        self.sequence_field.Bind(wx.EVT_TEXT,
                                 lambda event: self.update_preview())

        type_button = wx.Button(self, label=lang.control_label(
            "type_into_the_active_window",
            "&Type into the active window"))
        type_button.Bind(wx.EVT_BUTTON, self.on_type)
        close_button = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close",
            "&Close"))

        main = wx.BoxSizer(wx.VERTICAL)
        heading = wx.StaticText(
            self, label=lang.t(
                "dialogs", "switch_to_the_window_you_want",
                "Switch to the window you want filled, then press Type. "
                "ZKeypass minimises itself first if that option is on."))
        heading.Wrap(580)
        main.Add(heading, 0, wx.EXPAND | wx.ALL, 10)
        main.Add(read_row, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        main.Add(self.filter_box, 0, wx.EXPAND | wx.ALL, 10)
        main.Add(self.entry_list, 1, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)

        form, add = _labelled(self)
        # The target window field already sits in its own row above, so it is
        # deliberately left out of this grid.
        add(lang.t("dialogs", "sequence", "Sequence"), self.sequence_field)
        add(lang.t("dialogs", "common_sequences", "Common sequences"), self.sequence_choice)
        add(lang.t("dialogs", "what_will_be_typed", "What will be typed"), self.preview)
        main.Add(form, 0, wx.EXPAND | wx.ALL, 10)

        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(type_button, 0, wx.RIGHT, 6)
        row.Add(close_button, 0)
        main.Add(row, 0, wx.ALL, 10)
        self.SetSizer(main)

        self.window_field.SetValue(autotype.active_window_title())
        self.refresh()
        if preset_entry_id:
            self.select_entry(preset_entry_id)
        self.entry_list.SetFocus()

    # ------------------------------------------------------------------- data

    def refresh(self):
        needle = self.filter_box.GetValue().strip().lower()
        self.records = []
        for record in autotype_store.candidates(self.vault):
            if not (record.get("autotype") or {}).get("enabled", True):
                continue
            if needle and needle not in " ".join(
                    (record.get("title") or "", record.get("username") or "",
                     record.get("url") or "")).lower():
                continue
            self.records.append(record)
        self.entry_list.DeleteAllItems()
        for row, record in enumerate(self.records):
            self.entry_list.InsertItem(row, names.display_title(record))
            self.entry_list.SetItem(row, 1, record.get("username") or "")
            self.entry_list.SetItem(row, 2, names.display_site(record))
        if self.records:
            self.entry_list.Select(0)
            self.entry_list.Focus(0)
            self.on_selected(None)
        self.update_preview()

    def select_entry(self, entry_id):
        for row, record in enumerate(self.records):
            if record.get("id") == entry_id:
                self.entry_list.Select(row)
                self.entry_list.Focus(row)
                self.on_selected(None)
                return

    def current_record(self):
        row = self.entry_list.GetFirstSelected()
        if 0 <= row < len(self.records):
            return self.records[row]
        return None

    def on_selected(self, event):
        record = self.current_record()
        if not record:
            return
        settings = record.get("autotype") or {}
        for window, sequence in settings.get("associations", []):
            if autotype.window_matches(window, self.window_field.GetValue()):
                self.sequence_field.SetValue(sequence)
                self.update_preview()
                return
        self.sequence_field.SetValue(settings.get("sequence")
                                     or autotype_store.DEFAULT_SEQUENCE)
        self.update_preview()

    def on_preset(self, event):
        index = self.sequence_choice.GetSelection()
        if 0 <= index < len(PRESET_SEQUENCES):
            self.sequence_field.SetValue(PRESET_SEQUENCES[index][1])
            self.update_preview()

    def on_read_active(self, event):
        self.window_field.SetValue(autotype.active_window_title())
        record, score = autotype.best_match(self.records,
                                            self.window_field.GetValue())
        if record:
            self.select_entry(record.get("id"))
            self.SetTitle(lang.t(
                "dialogs", "auto_type_matched",
                "Auto-type - matched {title}",
                title=record.get('title')))
        self.update_preview()

    def update_preview(self):
        record = self.current_record()
        if not record:
            self.preview.SetValue("")
            return
        code = totp.format_code(totp.current_code(record)) \
            if record.get("totp_secret") else ""
        self.preview.SetValue(autotype.expand(self.sequence_field.GetValue(),
                                              record,
                                              record.get("group_name") or "",
                                              code))

    # ------------------------------------------------------------------ action

    def on_type(self, event=None):
        record = self.current_record()
        if not record:
            wx.MessageBox(lang.t(
                "errors", "choose_an_entry_to_type",
                "Choose an entry to type."), "Auto-type",
                          wx.OK | wx.ICON_WARNING, self)
            return
        sequence = self.sequence_field.GetValue().strip()
        complaint = autotype.validate_sequence(sequence)
        if complaint:
            wx.MessageBox(complaint, "Auto-type", wx.OK | wx.ICON_WARNING, self)
            return
        delay = int(self.settings.get("autotype_delay_ms") or 20)
        minimise = bool(self.settings.get("autotype_minimise"))
        if minimise:
            self.Iconize(True)
        wx.Yield()
        try:
            report = autotype_store.type_entry(self.vault, record,
                                               self.window_field.GetValue(),
                                               delay_ms=delay)
        except autotype.AutoTypeError as error:
            if minimise:
                self.Iconize(False)
            wx.MessageBox(str(error), "Auto-type", wx.OK | wx.ICON_ERROR, self)
            return
        self.result = report
        self.exit_code = wx.ID_OK
        self.EndModal(wx.ID_OK)


def _labelled(parent):
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


class AutoTypeEditDialog(wx.Dialog):
    """Per-entry auto-type settings: sequence and window associations."""

    def __init__(self, parent, vault, entry_id):
        super().__init__(parent, title=lang.t(
            "dialogs", "auto_type_settings_for_this_entry",
            "Auto-type settings for this entry"),
                         size=(660, 520))
        self.vault = vault
        self.entry_id = entry_id
        self.saved = False

        self.enabled_check = wx.CheckBox(self, label=lang.control_label(
            "allow_auto_type_for_this_entry",
            "Allow &auto-type for this entry"))
        self.enabled_check.SetValue(autotype_store.is_enabled(vault, entry_id))

        self.sequence_field = wx.TextCtrl(
            self, value=autotype_store.sequence_setting(vault, entry_id)
            or autotype_store.DEFAULT_SEQUENCE)
        self.sequence_field.SetName(lang.t("dialogs", "sequence", "Sequence"))
        self.preset_choice = wx.Choice(self, choices=[
            lang.sequence_name(name) for name, _value in PRESET_SEQUENCES])
        self.preset_choice.SetName(lang.t(
            "dialogs", "common_sequences",
            "Common sequences"))
        self.preset_choice.Bind(wx.EVT_CHOICE, self.on_preset)

        self.association_list = wx.ListCtrl(self, style=wx.LC_REPORT |
                                                       wx.LC_SINGLE_SEL)
        self.association_list.SetName(lang.t(
            "dialogs", "window_associations",
            "Window associations"))
        self.association_list.InsertColumn(0, lang.t(
            "dialogs", "window_title_pattern",
            "Window title pattern"), width=260)
        self.association_list.InsertColumn(1, lang.t(
            "dialogs", "sequence",
            "Sequence"), width=300)
        self.association_list.Bind(wx.EVT_LIST_ITEM_SELECTED, self.on_selected)

        self.window_field = wx.TextCtrl(self)
        self.window_field.SetName(lang.t(
            "dialogs", "window_pattern",
            "Window pattern"))
        self.window_choice = wx.Choice(self, choices=list(WINDOW_SUGGESTIONS))
        self.window_choice.SetName(lang.t(
            "dialogs", "common_window_patterns",
            "Common window patterns"))
        self.window_choice.Bind(wx.EVT_CHOICE, self.on_suggestion)
        self.association_sequence = wx.TextCtrl(self, value="{USERNAME}{TAB}{PASSWORD}{ENTER}")
        self.association_sequence.SetName(lang.t(
            "dialogs", "sequence_for_the_association",
            "Sequence for the association"))

        add_button = wx.Button(self, label=lang.control_label(
            "add_association",
            "&Add association"))
        update_button = wx.Button(self, label=lang.control_label(
            "update_selected",
            "&Update selected"))
        remove_button = wx.Button(self, label=lang.control_label(
            "remove_selected",
            "&Remove selected"))
        add_button.Bind(wx.EVT_BUTTON, self.on_add)
        update_button.Bind(wx.EVT_BUTTON, self.on_update)
        remove_button.Bind(wx.EVT_BUTTON, self.on_remove)
        read_button = wx.Button(self, label=lang.control_label(
            "read_active_window_title_2",
            "Read &active window title"))
        read_button.Bind(wx.EVT_BUTTON, self.on_read_active)
        browse_windows = wx.Button(self, label=lang.control_label(
            "list_open_windows",
            "List open &windows..."))
        browse_windows.Bind(wx.EVT_BUTTON, self.on_list_windows)

        show_button = wx.Button(self, label=lang.control_label(
            "show_what_would_be_typed",
            "&Show what would be typed"))
        show_button.Bind(wx.EVT_BUTTON, self.on_preview)
        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)

        form, add = _labelled(self)
        add(lang.t("dialogs", "default_sequence", "Default sequence"), self.sequence_field)
        add(lang.t("dialogs", "common_sequences", "Common sequences"), self.preset_choice)
        add(lang.t("dialogs", "window_pattern", "Window pattern"), self.window_field)
        add(lang.t(
            "dialogs", "common_window_patterns",
            "Common window patterns"), self.window_choice)
        add(lang.t(
            "dialogs", "sequence_for_the_association",
            "Sequence for the association"), self.association_sequence)

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (read_button, browse_windows):
            row.Add(button, 0, wx.RIGHT, 6)
        row2 = wx.BoxSizer(wx.HORIZONTAL)
        for button in (add_button, update_button, remove_button):
            row2.Add(button, 0, wx.RIGHT, 6)
        row3 = wx.BoxSizer(wx.HORIZONTAL)
        row3.Add(show_button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.enabled_check, 0, wx.ALL, 10)
        root.Add(form, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        root.Add(self.association_list, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)
        root.Add(row2, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)
        root.Add(row3, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 10)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 10)
        self.SetSizer(root)
        self.refresh()
        self.sequence_field.SetFocus()

    def refresh(self):
        self.associations = autotype_store.associations_for(self.vault,
                                                            self.entry_id)
        self.association_list.DeleteAllItems()
        for row, (window, sequence) in enumerate(self.associations):
            self.association_list.InsertItem(row, window)
            self.association_list.SetItem(row, 1, sequence)
        self._editing = None

    def on_preset(self, event):
        index = self.preset_choice.GetSelection()
        if 0 <= index < len(PRESET_SEQUENCES):
            self.sequence_field.SetValue(PRESET_SEQUENCES[index][1])

    def on_suggestion(self, event):
        index = self.window_choice.GetSelection()
        if 0 <= index < len(WINDOW_SUGGESTIONS):
            self.window_field.SetValue(WINDOW_SUGGESTIONS[index])

    def on_read_active(self, event):
        self.window_field.SetValue("*" + autotype.active_window_title() + "*")

    def on_list_windows(self, event):
        titles = autotype.visible_window_titles()
        if not titles:
            wx.MessageBox(lang.t(
                "errors", "no_titled_windows_were_found",
                "No titled windows were found."), "Auto-type",
                          wx.OK | wx.ICON_INFORMATION, self)
            return
        dialog = wx.SingleChoiceDialog(self, lang.t(
            "dialogs", "choose_a_window_to_match",
            "Choose a window to match:"),
                                       lang.t(
                                           "dialogs", "open_windows",
                                           "Open windows"), titles)
        if dialog.ShowModal() == wx.ID_OK:
            self.window_field.SetValue("*" + dialog.GetStringSelection() + "*")
        dialog.Destroy()

    def on_selected(self, event):
        row = event.GetIndex()
        if 0 <= row < len(self.associations):
            window, sequence = self.associations[row]
            self.window_field.SetValue(window)
            self.association_sequence.SetValue(sequence)

    def on_add(self, event):
        window = self.window_field.GetValue().strip()
        if not window:
            wx.MessageBox(lang.t(
                "errors", "give_the_window_pattern_to_match",
                "Give the window pattern to match."), "Auto-type",
                          wx.OK | wx.ICON_WARNING, self)
            return
        self.associations.append([window,
                                  self.association_sequence.GetValue().strip()])
        self.refresh()

    def on_update(self, event):
        row = self.association_list.GetFirstSelected()
        if row < 0:
            return
        self.associations[row] = [self.window_field.GetValue().strip(),
                                  self.association_sequence.GetValue().strip()]
        self.refresh()

    def on_remove(self, event):
        row = self.association_list.GetFirstSelected()
        if row >= 0:
            del self.associations[row]
            self.refresh()

    def on_preview(self, event):
        record = self.vault.get_entry(self.entry_id) or {}
        code = totp.format_code(totp.current_code(record)) \
            if record.get("totp_secret") else ""
        shown = autotype.expand(self.sequence_field.GetValue(), record,
                                record.get("group_name") or "", code)
        wx.MessageBox(lang.t(
            "errors", "zkeypass_would_type",
            "ZKeypass would type:\n\n{shown}",
            shown=shown), lang.t(
            "dialogs", "auto_type_preview",
            "Auto-type preview"),
                      wx.OK | wx.ICON_INFORMATION, self)

    def on_ok(self, event):
        complaint = autotype.validate_sequence(self.sequence_field.GetValue())
        if complaint:
            wx.MessageBox(complaint, "Auto-type", wx.OK | wx.ICON_WARNING, self)
            return
        for window, sequence in self.associations:
            complaint = autotype.validate_sequence(sequence)
            if complaint:
                wx.MessageBox(f"{window}: {complaint}", "Auto-type",
                              wx.OK | wx.ICON_WARNING, self)
                return
        autotype_store.set_enabled(self.vault, self.entry_id,
                                  self.enabled_check.GetValue())
        autotype_store.set_sequence(self.vault, self.entry_id,
                                    self.sequence_field.GetValue().strip())
        autotype_store.set_associations(self.vault, self.entry_id,
                                        self.associations)
        self.saved = True
        event.Skip()


class PasskeysDialog(wx.Dialog):
    """Create, inspect and remove the passkeys stored on an entry."""

    def __init__(self, parent, vault, entry_id, settings=None):
        super().__init__(parent, title=lang.t(
            "dialogs", "passkeys",
            "Passkeys"), size=(720, 540))
        self.vault = vault
        self.entry_id = entry_id
        self.settings = settings or Settings.load()
        self.changed = False

        self.listbox = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
        self.listbox.SetName(lang.t(
            "dialogs", "passkeys_for_this_entry",
            "Passkeys for this entry"))
        for index, (heading, width) in enumerate(((lang.t(
            "dialogs", "website",
            "Website"), 220),
                                                  (lang.t(
                                                      "dialogs", "user_name",
                                                      "User name"), 180),
                                                  (lang.t(
                                                      "dialogs", "algorithm",
                                                      "Algorithm"), 200),
                                                  (lang.t(
                                                      "dialogs", "credential",
                                                      "Credential"), 100))):
            self.listbox.InsertColumn(index, heading, width=width)

        self.rp_field = wx.TextCtrl(self)
        self.rp_field.SetName(lang.t("dialogs", "website", "Website"))
        self.username_field = wx.TextCtrl(self)
        self.username_field.SetName(lang.t("dialogs", "user_name", "User name"))
        self.handle_field = wx.TextCtrl(self)
        self.handle_field.SetName(lang.t(
            "dialogs", "user_handle_blank_for_a_random",
            "User handle, blank for a random one"))
        self.algorithm_choice = wx.Choice(self, choices=[name for name in
                                                         passkeys.ALGORITHM_IDS])
        self.algorithm_choice.SetName(lang.t(
            "dialogs", "algorithm",
            "Algorithm"))
        self.algorithm_choice.SetStringSelection(
            self.settings.get("passkey_algorithm") or "ES256")

        add_button = wx.Button(self, label=lang.control_label(
            "create_passkey",
            "&Create passkey"))
        details_button = wx.Button(self, label=lang.control_label(
            "show_details",
            "Show &details"))
        remove_button = wx.Button(self, label=lang.control_label(
            "remove_selected",
            "&Remove selected"))
        add_button.Bind(wx.EVT_BUTTON, self.on_add)
        details_button.Bind(wx.EVT_BUTTON, self.on_details)
        remove_button.Bind(wx.EVT_BUTTON, self.on_remove)
        self.listbox.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.on_details)

        form, add = _labelled(self)
        add(lang.t("dialogs", "website", "Website"), self.rp_field)
        add(lang.t("dialogs", "user_name", "User name"), self.username_field)
        add(lang.t(
            "dialogs", "user_handle_blank_for_a_random",
            "User handle, blank for a random one"), self.handle_field)
        add(lang.t("dialogs", "algorithm", "Algorithm"), self.algorithm_choice)

        explanation = wx.StaticText(
            self, label=lang.t(
                "dialogs", "a_passkey_is_an_elliptic_curve",
                "A passkey is an elliptic curve key pair kept inside the "
                "database. ZKeypass can create one, show the public part a "
                "site needs, and sign an assertion on request. Stored with "
                "the KeePassXC attribute names, so a KeePass database keeps "
                "them both ways."))
        explanation.Wrap(660)

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (add_button, details_button, remove_button):
            row.Add(button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(self.listbox, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.ALL, 10)
        root.Add(form, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        root.Add(explanation, 0, wx.EXPAND | wx.ALL, 10)
        close = self.CreateButtonSizer(wx.CLOSE)
        if close:
            root.Add(close, 0, wx.ALIGN_RIGHT | wx.ALL, 10)
        self.SetSizer(root)
        self.refresh()
        self.rp_field.SetFocus()

    def refresh(self):
        self.records = passkeys.passkeys_for_entry(self.vault, self.entry_id)
        self.listbox.DeleteAllItems()
        for row, record in enumerate(self.records):
            try:
                algorithm = passkeys.ALGORITHM_NAMES.get(
                    passkeys.algorithm_of(
                        passkeys.load_private_key(record["private_key_pem"])),
                    "unknown")
            except passkeys.PasskeyError:
                algorithm = "unreadable"
            self.listbox.InsertItem(row, record.get("relying_party") or "")
            self.listbox.SetItem(row, 1, record.get("username") or "")
            self.listbox.SetItem(row, 2, algorithm)
            self.listbox.SetItem(
                row, 3, passkeys.b64url_encode(record["credential_id"])[:12])

    def on_add(self, event):
        relying_party = self.rp_field.GetValue().strip()
        if not relying_party:
            record = self.vault.get_entry(self.entry_id) or {}
            relying_party = browser._host_of(record.get("url"))
        if not relying_party:
            wx.MessageBox(lang.t(
                "errors", "give_the_website_usually_the_web",
                "Give the website, usually the web address the passkey "
                "belongs to."), lang.t(
                              "dialogs", "passkeys",
                              "Passkeys"),
                          wx.OK | wx.ICON_WARNING, self)
            return
        record = self.vault.get_entry(self.entry_id) or {}
        handle = self.handle_field.GetValue().strip()
        try:
            new = passkeys.new_passkey(
                relying_party,
                self.username_field.GetValue().strip() or record.get("username")
                or "",
                user_handle=handle.encode("utf-8") if handle else None,
                algorithm=self.algorithm_choice.GetStringSelection() or "ES256")
            passkeys.store_passkey(self.vault, self.entry_id, new)
        except passkeys.PasskeyError as error:
            wx.MessageBox(str(error), lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_ERROR, self)
            return
        self.settings["passkey_algorithm"] = new["algorithm"] == \
            passkeys.ALGORITHM_ES256 and "ES256" or self.algorithm_choice \
            .GetStringSelection()
        self.changed = True
        self.rp_field.SetValue("")
        self.username_field.SetValue("")
        self.handle_field.SetValue("")
        self.refresh()
        wx.MessageBox(lang.t(
            "errors", "the_passkey_has_been_created_and",
            "The passkey has been created and stored in this entry. Switch "
            "to Passkeys in the entry editor to see it."),
                      lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_INFORMATION, self)

    def on_details(self, event):
        row = self.listbox.GetFirstSelected()
        if row < 0 or row >= len(self.records):
            return
        record = self.records[row]
        try:
            private_key = passkeys.load_private_key(record["private_key_pem"])
            cose = passkeys.cose_public_key(private_key).hex()
            algorithm = passkeys.ALGORITHM_NAMES.get(
                passkeys.algorithm_of(private_key), "unknown")
        except passkeys.PasskeyError as error:
            wx.MessageBox(str(error), lang.t("dialogs", "passkeys", "Passkeys"), wx.OK | wx.ICON_ERROR, self)
            return
        text = (
            lang.t(
                "dialogs", "website_user_name_user_handle_algorithm",
                "Website: {relying_party}\nUser name: {username}\nUser "
                "handle: {user_handle}\nAlgorithm: {algorithm}\nCredential "
                "id: {credential_id}\nPublic key, COSE form, hex: {cose}\n\n"
                "The private half never leaves the database.",
                relying_party=record.get('relying_party') or lang.t(
                    "dialogs", "none",
                    "(none)"),
                username=record.get('username') or lang.t(
                    "dialogs", "none",
                    "(none)"),
                user_handle=record.get('user_handle') or lang.t(
                    "dialogs", "none",
                    "(none)"),
                algorithm=algorithm,
                credential_id=passkeys.b64url_encode(record['credential_id']),
                cose=cose))
        dialog = _TextDialog(self, lang.t(
            "dialogs", "passkey_details",
            "Passkey details"), text)
        dialog.ShowModal()
        dialog.Destroy()

    def on_remove(self, event):
        row = self.listbox.GetFirstSelected()
        if row < 0:
            return
        if wx.MessageBox(lang.t(
            "errors", "remove_this_passkey_the_site_will",
            "Remove this passkey? The site will no longer accept it."), lang.t("dialogs", "passkeys", "Passkeys"), wx.YES_NO | wx.NO_DEFAULT |
                         wx.ICON_QUESTION, self) != wx.YES:
            return
        passkeys.delete_passkey(self.vault, self.entry_id, row)
        self.changed = True
        self.refresh()


class SuggestNamesDialog(wx.Dialog):
    """Short names for entries that have none, or only a web address.

    Each suggestion is a checkable line, "current name, becomes, new name",
    all checked to start with.  Space unchecks one.  Rename changes only the
    checked entries; nothing changes until Rename is pressed.

    Suggestions are first made from the address alone, on this computer.
    "Look up real names online" can replace them with each site's own page
    title, after the user agrees.  While it runs, an activity feed and a
    progress bar show every site as it is looked up; both go away when the
    lookup is finished.
    """

    WORKERS = 4

    def __init__(self, parent, vault, settings=None):
        super().__init__(parent, title=lang.t(
            "dialogs", "suggest_names",
            "Suggest names"), size=(720, 600),
                         style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        self.vault = vault
        self.settings = settings if settings is not None else Settings.load()
        self.renamed = 0
        self.rows = []
        for entry in vault.entries():
            if not names.needs_name(entry):
                continue
            new = names.suggest(entry)
            address = entry.get("url") or entry.get("title") or ""
            if new and new != (entry.get("title") or "").strip():
                self.rows.append([entry["id"], entry.get("title") or "", new,
                                  address])
        # Shared with the lookup threads, which must never touch a window
        # that has been closed.
        import threading
        import types

        self.state = types.SimpleNamespace(closed=False, stop=threading.Event())

        intro = wx.StaticText(
            self, label=lang.t(
                "dialogs", "these_entries_have_no_name_or",
                "These entries have no name, or only a web address as their "
                "name. Each line shows the name now and the suggested one, "
                "made from the web address on this computer. Space checks or "
                "unchecks a line. Rename changes the checked entries."))
        intro.Wrap(680)
        label = wx.StaticText(self, label=lang.control_label(
            "suggestions_2",
            "&Suggestions"))
        self.choices = wx.CheckListBox(self, choices=[
            self.line(row) for row in self.rows])
        self.choices.SetName(lang.t("dialogs", "suggestions", "Suggestions"))
        for index in range(len(self.rows)):
            self.choices.Check(index, True)
        if self.rows:
            self.choices.SetSelection(0)

        self.lookup_button = wx.Button(
            self, label=lang.control_label(
                "look_up_real_names_online",
                "&Look up real names online..."))
        self.lookup_button.Bind(wx.EVT_BUTTON, self.on_lookup)
        all_button = wx.Button(self, label=lang.control_label(
            "check_all",
            "Check &all"))
        none_button = wx.Button(self, label=lang.control_label(
            "check_none",
            "Check &none"))
        self.rename_button = wx.Button(self, id=wx.ID_OK,
                                       label=lang.control_label(
                                           "rename_the_checked_entries",
                                           "&Rename the checked entries"))
        cancel = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "cancel",
            "&Cancel"))
        all_button.Bind(wx.EVT_BUTTON, lambda event: self.check_all(True))
        none_button.Bind(wx.EVT_BUTTON, lambda event: self.check_all(False))
        self.rename_button.Bind(wx.EVT_BUTTON, self.on_rename)
        self.Bind(wx.EVT_BUTTON, self.on_cancel, id=wx.ID_CANCEL)
        self.Bind(wx.EVT_CLOSE, self.on_cancel)

        # The activity feed: hidden until a lookup runs, hidden again after.
        self.feed = wx.Panel(self)
        feed_label = wx.StaticText(self.feed, label=lang.control_label(
            "lookup_activity_2",
            "Lookup &activity"))
        self.feed_text = wx.TextCtrl(
            self.feed, style=wx.TE_MULTILINE | wx.TE_READONLY, size=(-1, 120))
        self.feed_text.SetName(lang.t(
            "dialogs", "lookup_activity",
            "Lookup activity"))
        self.progress = wx.Gauge(self.feed, range=1)
        self.progress.SetName(lang.t(
            "dialogs", "lookup_progress",
            "Lookup progress"))
        self.stop_button = wx.Button(self.feed, label=lang.control_label(
            "stop_the_lookup",
            "S&top the lookup"))
        self.stop_button.Bind(wx.EVT_BUTTON, self.on_stop)
        feed_sizer = wx.BoxSizer(wx.VERTICAL)
        feed_sizer.Add(feed_label, 0, wx.BOTTOM, 4)
        feed_sizer.Add(self.feed_text, 1, wx.EXPAND | wx.BOTTOM, 6)
        feed_sizer.Add(self.progress, 0, wx.EXPAND | wx.BOTTOM, 6)
        feed_sizer.Add(self.stop_button, 0)
        self.feed.SetSizer(feed_sizer)
        self.feed.Hide()

        self.status = wx.StaticText(self, label="")
        self.status.SetName(lang.t(
            "dialogs", "suggest_names_status",
            "Suggest names status"))

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (self.lookup_button, all_button, none_button,
                       self.rename_button, cancel):
            row.Add(button, 0, wx.RIGHT, 6)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(intro, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(label, 0, wx.LEFT | wx.RIGHT, 10)
        root.Add(self.choices, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(self.feed, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        root.Add(self.status, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.ALL, 10)
        self.SetSizer(root)
        self.choices.SetFocus()

    @staticmethod
    def line(row):
        _entry_id, old, new, _address = row
        return lang.t(
            "dialogs", "becomes",
            "{old}, becomes, {new}",
            old=old or lang.t("dialogs", "no_name", "no name"),
            new=new)

    def check_all(self, checked):
        for index in range(self.choices.GetCount()):
            self.choices.Check(index, checked)

    # ------------------------------------------------------------ online

    def sites(self):
        """Each site once: {front page: [row indexes]}."""
        from . import names_online

        found = {}
        for index, row in enumerate(self.rows):
            page = names_online.front_page(row[3])
            if page:
                found.setdefault(page, []).append(index)
        return found

    def ask_consent(self, count):
        """True when the user agrees to go online this time."""
        if self.settings.get("names_online_allowed"):
            return True
        dialog = wx.MessageDialog(
            self,
            lang.plural(
                "dialogs", "lookup_ask", count,
                "Look up the real name of {count} site online?\n\n{details}",
                "Look up the real names of {count} sites online?\n\n{details}",
                details=lang.t(
                    "dialogs", "lookup_ask_details",
                    "ZKeypass will open each site's front page, such as "
                    "https://example.com/, and read only its page title. The "
                    "rest of the stored address is left out, and nothing from "
                    "your database is sent: no user names, passwords or notes. "
                    "The sites will see that this computer visited them, as "
                    "with any browser visit.\n\nNothing changes until you "
                    "press Rename.")),
            lang.t("dialogs", "look_up_names_online", "Look up names online"),
            wx.YES_NO | wx.CANCEL | wx.ICON_QUESTION)
        dialog.SetYesNoCancelLabels(lang.control_label(
            "allow_this_time",
            "Allow &this time"), lang.control_label(
            "always_allow",
            "Always a&llow"),
                                    lang.control_label("cancel", "&Cancel"))
        answer = dialog.ShowModal()
        dialog.Destroy()
        if answer == wx.ID_NO:
            self.settings["names_online_allowed"] = True
            try:
                self.settings.save()
            except Exception:
                pass
            return True
        return answer == wx.ID_YES

    def on_lookup(self, event=None):
        sites = self.sites()
        if not sites:
            self.status.SetLabel(lang.t(
                "dialogs", "none_of_these_entries_has_a",
                "None of these entries has a web address to look up."))
            return
        if not self.ask_consent(len(sites)):
            self.status.SetLabel(lang.t(
                "dialogs", "nothing_was_looked_up_zkeypass_stayed",
                "Nothing was looked up. ZKeypass stayed offline."))
            return
        self.found = 0
        self.failed = 0
        self.done = 0
        self.total = len(sites)
        self.state.stop.clear()
        self.feed_text.SetValue("")
        self.progress.SetRange(self.total)
        self.progress.SetValue(0)
        self.feed.Show()
        self.lookup_button.Disable()
        self.rename_button.Disable()
        self.Layout()
        self.stop_button.SetFocus()
        self.report(lang.plural(
            "actions_announcements", "looking_up_sites", self.total,
            "Looking up {count} site, {at_once} at a time.",
            "Looking up {count} sites, {at_once} at a time.",
            at_once=min(self.WORKERS, self.total)))
        import threading

        threading.Thread(target=self.run_lookups, args=(sites, self.state),
                         daemon=True).start()

    def run_lookups(self, sites, state):
        """Worker thread: look sites up, posting each result to the window."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        from . import names_online

        def post(handler, *args):
            def deliver():
                if not state.closed:
                    handler(*args)
            wx.CallAfter(deliver)

        def one(page):
            if state.stop.is_set():
                return page, "", "stopped"
            post(self.report, lang.t(
                "actions_announcements", "looking_up",
                "Looking up {site} ...",
                site=names.site_of(page)))
            title, problem = names_online.fetch_title(page)
            return page, title, problem

        with ThreadPoolExecutor(max_workers=self.WORKERS) as pool:
            futures = [pool.submit(one, page) for page in sites]
            for future in as_completed(futures):
                try:
                    page, title, problem = future.result()
                except Exception as error:   # never let a thread die silently
                    page, title, problem = "", "", str(error)
                post(self.on_result, page, sites.get(page, []), title, problem)
                if state.stop.is_set():
                    for waiting in futures:
                        waiting.cancel()
        post(self.on_finished)

    def report(self, text):
        self.feed_text.AppendText(text + "\n")
        self.status.SetLabel(text)

    def on_result(self, page, indexes, title, problem):
        from . import names_online

        self.done += 1
        self.progress.SetValue(min(self.done, self.total))
        site = names.site_of(page) or lang.t("dialogs", "a_site", "a site")
        if problem == "stopped":
            return
        name = names_online.choose_name(title, page) if title else ""
        if not name:
            self.failed += 1
            why = problem or lang.t(
                "dialogs", "its_title_is_not_a_name",
                "its title, {title!r}, is not a name",
                title=title)
            self.report(lang.t(
                "actions_announcements", "kept_the_suggestion",
                "{site}: kept the suggestion, {why}.",
                site=site,
                why=why))
            return
        self.found += 1
        for index in indexes:
            self.rows[index][2] = name
            self.choices.SetString(index, self.line(self.rows[index]))
        self.report(lang.t(
            "actions_announcements", "found",
            "{site}: found {name}.",
            site=site,
            name=name))

    def on_stop(self, event=None):
        self.state.stop.set()
        self.stop_button.Disable()
        self.report(lang.t(
            "actions_announcements", "stopping_after_the_sites_already_being",
            "Stopping after the sites already being looked up."))

    def on_finished(self):
        self.feed.Hide()
        self.stop_button.Enable()
        self.lookup_button.Enable()
        self.rename_button.Enable()
        self.Layout()
        stopped = lang.t("dialogs", "stopped_early", " Stopped early.") if self.state.stop.is_set() else ""
        self.status.SetLabel(
            lang.plural(
                "dialogs", "lookup_finished", self.found,
                "Lookup finished.{stopped} {count} real name found, {failed} "
                "kept as suggested. Check the list, then press Rename.",
                "Lookup finished.{stopped} {count} real names found, {failed} "
                "kept as suggested. Check the list, then press Rename.",
                stopped=stopped, failed=self.failed))
        self.choices.SetFocus()

    # ------------------------------------------------------------ results

    def on_cancel(self, event=None):
        self.state.stop.set()
        self.state.closed = True
        if self.IsModal():
            self.EndModal(wx.ID_CANCEL)
        else:
            self.Destroy()

    def on_rename(self, event):
        self.state.stop.set()
        self.state.closed = True
        for index, (entry_id, _old, new, _address) in enumerate(self.rows):
            if self.choices.IsChecked(index):
                self.vault.rename_entry(entry_id, new)
                self.renamed += 1
        self.EndModal(wx.ID_OK)


class _TextDialog(wx.Dialog):
    """Read-only text with a copy button, for details and reports."""

    def __init__(self, parent, title, text, width=760, height=520):
        super().__init__(parent, title=title, size=(width, height))
        control = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY |
                                           wx.TE_RICH2)
        control.SetName(title)
        control.SetValue(text)
        copy_button = wx.Button(self, label=lang.control_label(
            "copy_all",
            "&Copy all"))
        copy_button.Bind(wx.EVT_BUTTON,
                         lambda event: self.copy(text))
        close_button = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close",
            "&Close"))
        row = wx.BoxSizer(wx.HORIZONTAL)
        row.Add(copy_button, 0, wx.RIGHT, 6)
        row.Add(close_button, 0)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(control, 1, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.ALL, 10)
        self.SetSizer(root)
        control.SetFocus()

    @staticmethod
    def copy(text):
        from . import clipboard

        clipboard.copy_plain(text)


class YubiKeyDialog(wx.Dialog):
    """Test a hardware security key and choose the challenge-response slot."""

    def __init__(self, parent, settings=None):
        super().__init__(parent, title=lang.t(
            "dialogs", "security_key",
            "Security key"), size=(660, 460))
        self.settings = settings or Settings.load()
        self.answer = ""

        self.slot_choice = wx.Choice(self, choices=[lang.t(
            "dialogs", "slot_1_long_press",
            "Slot 1, long press"),
                                                    lang.t(
                                                        "dialogs", "slot_2_short_press",
                                                        "Slot 2, short press")])
        self.slot_choice.SetName(lang.t("dialogs", "slot", "Slot"))
        self.slot_choice.SetSelection(int(self.settings.get("yubikey_slot")
                                          or 1) - 1)
        self.status = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.status.SetName(lang.t(
            "dialogs", "security_key_status",
            "Security key status"))
        detect = wx.Button(self, label=lang.control_label(
            "look_for_a_security_key",
            "&Look for a security key"))
        detect.Bind(wx.EVT_BUTTON, self.on_detect)
        test = wx.Button(self, label=lang.control_label(
            "send_a_test_challenge",
            "&Send a test challenge"))
        test.Bind(wx.EVT_BUTTON, self.on_test)
        close = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "close",
            "&Close"))

        explanation = wx.StaticText(
            self, label=lang.t(
                "dialogs", "a_security_key_can_be_part",
                "A security key can be part of the master key, so the "
                "database cannot be opened without the physical key. The "
                "challenge and its answer are never written to the database. "
                "ZKeypass sends the challenge straight to the key over USB and "
                "never stores the answer."))
        explanation.Wrap(600)

        form, add = _labelled(self)
        add(lang.t("dialogs", "slot", "Slot"), self.slot_choice)
        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (detect, test, close):
            row.Add(button, 0, wx.RIGHT, 6)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(explanation, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(form, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        root.Add(row, 0, wx.LEFT | wx.RIGHT | wx.TOP, 10)
        root.Add(self.status, 1, wx.EXPAND | wx.ALL, 10)
        self.SetSizer(root)
        self.status.SetValue(lang.t(
            "dialogs", "press_look_for_a_security_key",
            "Press Look for a security key to begin.\n"))
        detect.SetFocus()

    def slot(self):
        return 1 if self.slot_choice.GetSelection() <= 0 else 2

    def on_detect(self, event):
        from . import yubikey

        lines = yubikey.describe_keys()
        if not lines:
            self.status.SetValue(lang.t(
                "dialogs", "no_security_key_was_found_plug",
                "No security key was found. Plug one in and press Look for a "
                "security key again.\n"))
            return
        self.status.SetValue("\n".join(lines) + "\n")

    def on_test(self, event):
        from . import yubikey

        try:
            answer = yubikey.challenge_response(b"ZKPass test challenge",
                                                self.slot())
        except (yubikey.YubiKeyError, OSError) as error:
            self.status.SetValue(lang.t(
                "dialogs", "the_security_key_did_not_answer",
                "The security key did not answer:\n{error}\n",
                error=error))
            return
        self.answer = answer.hex()
        self.status.SetValue(
            lang.t(
                "dialogs", "the_security_key_answered_the_first",
                "The security key answered. The first four bytes of the "
                "answer were {answer}.\nThe same challenge always produces "
                "the same answer on the same key, which is what makes it "
                "usable.\n",
                answer=self.answer[:8]))
        self.settings["yubikey_slot"] = self.slot()
        self.settings.save()


class BrowserDialog(wx.Dialog):
    """Start, stop and inspect the browser integration service."""

    def __init__(self, parent, frame):
        super().__init__(parent, title=lang.t(
            "dialogs", "browser_integration",
            "Browser integration"), size=(700, 520))
        self.frame = frame
        self.status = wx.TextCtrl(self, style=wx.TE_MULTILINE | wx.TE_READONLY)
        self.status.SetName(lang.t(
            "dialogs", "browser_integration_status",
            "Browser integration status"))
        start = wx.Button(self, label=lang.control_label("start", "&Start"))
        stop = wx.Button(self, label=lang.control_label("stop", "S&top"))
        refresh = wx.Button(self, label=lang.control_label(
            "refresh",
            "&Refresh"))
        manifest = wx.Button(self, label=lang.control_label(
            "write_the_browser_manifest",
            "Write the &browser manifest"))
        forget = wx.Button(self, label=lang.control_label(
            "forget_all_paired_browsers",
            "&Forget all paired browsers"))
        start.Bind(wx.EVT_BUTTON, lambda event: self.toggle(True))
        stop.Bind(wx.EVT_BUTTON, lambda event: self.toggle(False))
        refresh.Bind(wx.EVT_BUTTON, lambda event: self.refresh())
        manifest.Bind(wx.EVT_BUTTON, self.on_manifest)
        forget.Bind(wx.EVT_BUTTON, self.on_forget)

        explanation = wx.StaticText(
            self, label=lang.t(
                "dialogs", "a_browser_extension_can_ask_zkeypass",
                "A browser extension can ask ZKeypass for logins, ask for a "
                "generated password, ask for a verification code and store a "
                "new login. Every message after the handshake is encrypted "
                "with ChaCha20-Poly1305. Pairing always needs your approval, "
                "and the service listens on this machine only."))
        explanation.Wrap(640)

        row = wx.BoxSizer(wx.HORIZONTAL)
        for button in (start, stop, refresh, manifest, forget):
            row.Add(button, 0, wx.RIGHT, 6)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(explanation, 0, wx.EXPAND | wx.ALL, 10)
        root.Add(row, 0, wx.LEFT | wx.RIGHT, 10)
        root.Add(self.status, 1, wx.EXPAND | wx.ALL, 10)
        close = self.CreateButtonSizer(wx.CLOSE)
        if close:
            root.Add(close, 0, wx.ALIGN_RIGHT | wx.ALL, 10)
        self.SetSizer(root)
        self.refresh()
        start.SetFocus()

    def refresh(self):
        server = getattr(self.frame, "browser_server", None)
        lines = []
        if server and getattr(server, "running", False):
            lines.append(lang.t(
                "dialogs", "listening_on",
                "Listening on {host}:{port}.",
                host=server.host,
                port=server.port))
            lines.append(lang.plural(
                "dialogs", "connections_so_far", server.connections,
                "{count} connection so far.", "{count} connections so far."))
        else:
            lines.append(lang.t(
                "dialogs", "the_service_is_stopped",
                "The service is stopped."))
        associations = {}
        try:
            associations = self.frame.browser_bridge.associations or {}
        except Exception:
            associations = {}
        if associations:
            lines.append(lang.t(
                "dialogs", "paired_browsers",
                "Paired browsers:"))
            for identifier, record in associations.items():
                lines.append(lang.t(
                    "dialogs", "identifier",
                    "  {name}, identifier {identifier}...",
                    name=record.get('name') or lang.t(
                        "dialogs", "unnamed",
                        "unnamed"),
                    identifier=identifier[:12]))
        else:
            lines.append(lang.t(
                "dialogs", "no_browser_is_paired_yet",
                "No browser is paired yet."))
        lines.append("")
        lines.append(lang.t(
            "dialogs", "a_browser_extension_uses_one_of",
            "A browser extension uses one of two transports: a loopback "
            "socket, or native messaging where the browser starts ZKeypass "
            "itself. The manifest for native messaging is written inside the "
            "program folder."))
        self.status.SetValue("\n".join(lines) + "\n")

    def toggle(self, start):
        try:
            if start:
                self.frame.start_browser_server()
            else:
                self.frame.stop_browser_server()
        except browser.BrowserError as error:
            wx.MessageBox(str(error), lang.t(
                "dialogs", "browser_integration",
                "Browser integration"),
                          wx.OK | wx.ICON_ERROR, self)
        self.refresh()

    def on_manifest(self, event):
        path = os.path.join(paths.BASE_DIR, "zkeypass_native_host.json")
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(browser.native_manifest(paths.LAUNCHER))
        except OSError as error:
            wx.MessageBox(lang.t(
                "errors", "could_not_write_the_manifest",
                "Could not write the manifest: {error}",
                error=error),
                          lang.t(
                              "dialogs", "browser_integration",
                              "Browser integration"), wx.OK | wx.ICON_ERROR, self)
            return
        wx.MessageBox(
            lang.t(
                "errors", "the_manifest_was_written_to_registering",
                "The manifest was written to\n{path}\n\nRegistering it with "
                "a browser is a manual step, because ZKeypass never writes "
                "outside its own folder.",
                path=path), lang.t(
                "dialogs", "browser_integration",
                "Browser integration"), wx.OK |
            wx.ICON_INFORMATION, self)

    def on_forget(self, event):
        if wx.MessageBox(lang.t(
            "errors", "forget_every_paired_browser",
            "Forget every paired browser?"), lang.t(
            "dialogs", "browser_integration",
            "Browser integration"),
                         wx.YES_NO | wx.NO_DEFAULT | wx.ICON_QUESTION,
                         self) != wx.YES:
            return
        try:
            self.frame.browser_bridge.associations = {}
            from .browser import _save_associations

            _save_associations(self.frame.vault,
                               self.frame.browser_bridge.associations)
            self.frame.auto_save()
        except Exception as error:
            wx.MessageBox(str(error), lang.t(
                "dialogs", "browser_integration",
                "Browser integration"), wx.OK |
                          wx.ICON_ERROR, self)
        self.refresh()
