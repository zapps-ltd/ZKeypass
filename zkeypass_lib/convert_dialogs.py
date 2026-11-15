"""Two dialogs: save the open database in the other format, and export its contents.

Both are built from ordinary wx widgets with a labelled grid of controls, so
NVDA and JAWS announce every field, its caption and its current value without
any custom drawing.
"""

import os
import time

import wx

from . import paths
from .dialogs import ask_yes_no, labelled, make_key_file
from .convert import EXPORT_LABELS, EXPORT_SUFFIXES
from . import lang


class SaveAsDialog(wx.Dialog):
    """Write the open database out as a .kdbx or a .zkp file."""

    def __init__(self, parent, current_path="", suggest_kind="kdbx"):
        title = lang.t("dialogs", "save_database_as", "Save database as")
        super().__init__(parent, title=title, size=(640, 520))
        from .kdbx import CIPHER_CHOICES, CIPHER_LABELS, KDF_CHOICES, KDF_LABELS

        self.result = None
        grid, add = labelled(self)

        self.format_choice = add(lang.t("dialogs", "save_as", "Save as"), lambda: wx.Choice(self, choices=[
            lang.t(
                "dialogs", "keepass_database_opens_in_keepassxc_kdbx",
                "KeePass database, opens in KeePassXC (*.kdbx)"),
            lang.t(
                "dialogs", "zkeypass_database_zkeypass_only_zkp",
                "ZKeypass database, ZKeypass only (*.zkp)"),
        ]))
        self.format_choice.SetSelection(0 if suggest_kind == "kdbx" else 1)
        self.format_choice.SetName(lang.t(
            "dialogs", "save_as_format",
            "Save as format"))
        self.format_choice.Bind(wx.EVT_CHOICE, self.on_format)

        stem = os.path.splitext(os.path.basename(current_path or "passwords"))[0] \
            or "passwords"
        suffix = ".kdbx" if suggest_kind == "kdbx" else ".zkp"
        self.name_field = add(lang.t("dialogs", "file_name", "File name"), lambda: wx.TextCtrl(self, value=stem + suffix))
        self.name_field.SetName(lang.t("dialogs", "file_name", "File name"))
        self.folder_field = add(lang.t("dialogs", "folder", "Folder"), lambda: wx.TextCtrl(self, value=paths.BASE_DIR))
        self.folder_field.SetName(lang.t("dialogs", "folder", "Folder"))
        browse = wx.Button(self, label=lang.control_label(
            "browse_for_a_folder_2",
            "&Browse for a folder..."))
        browse.SetName(lang.t(
            "dialogs", "browse_for_a_folder",
            "Browse for a folder"))
        browse.Bind(wx.EVT_BUTTON, self.on_browse)

        self.keyfile_field = add(lang.t(
            "dialogs", "key_file_keepass_format_only_optional",
            "Key file (KeePass format only, optional)"),
                                 lambda: wx.TextCtrl(self))
        self.keyfile_field.SetName(lang.t("dialogs", "key_file", "Key file"))
        create_key = wx.Button(self, label=lang.control_label(
            "create_a_key_file_2",
            "Create a key &file..."))
        create_key.SetName(lang.t(
            "dialogs", "create_a_key_file",
            "Create a key file"))
        create_key.Bind(wx.EVT_BUTTON, self.on_create_keyfile)

        self.cipher_choice = add(lang.t(
            "dialogs", "encryption_method",
            "Encryption method"), lambda: wx.Choice(
            self, choices=[CIPHER_LABELS[name] for name in CIPHER_CHOICES]))
        self.cipher_choice.SetSelection(0)
        self.cipher_choice.SetName(lang.t(
            "dialogs", "encryption_method",
            "Encryption method"))
        self.kdf_choice = add(lang.t(
            "dialogs", "password_hardening",
            "Password hardening"), lambda: wx.Choice(
            self, choices=[KDF_LABELS[name] for name in KDF_CHOICES]))
        self.kdf_choice.SetSelection(0)
        self.kdf_choice.SetName(lang.t(
            "dialogs", "password_hardening",
            "Password hardening"))

        self.password_field = add(lang.t(
            "dialogs", "master_password_for_the_new_copy",
            "Master password for the new copy"),
                                  lambda: wx.TextCtrl(self, style=wx.TE_PASSWORD))
        self.password_field.SetName(lang.t(
            "dialogs", "master_password_for_the_new_copy",
            "Master password for the new copy"))
        self.confirm_field = add(lang.t(
            "dialogs", "repeat_that_password",
            "Repeat that password"),
                                 lambda: wx.TextCtrl(self, style=wx.TE_PASSWORD))
        self.confirm_field.SetName(lang.t(
            "dialogs", "repeat_that_password",
            "Repeat that password"))

        self.attachments_check = add(
            lang.t("dialogs", "stored_files", "Stored files"),
            lambda: wx.CheckBox(self, label=lang.control_label(
                "copy_stored_files_into_the_new",
                "Copy &stored files into the new copy")))
        self.attachments_check.SetValue(True)
        self.attachments_check.SetName(lang.t(
            "dialogs", "copy_stored_files",
            "Copy stored files"))

        self.keyfile_field.Enable(suggest_kind == "kdbx")

        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        for control in (browse, create_key):
            root.Add(control, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 12)
        root.Insert(0, grid, 0, wx.EXPAND | wx.ALL, 12)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizer(root)
        self.name_field.SetFocus()
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)

    # ------------------------------------------------------------- callbacks

    def current_kind(self):
        return "kdbx" if self.format_choice.GetSelection() == 0 else "zkp"

    def on_format(self, event=None):
        kind = self.current_kind()
        suffix = ".kdbx" if kind == "kdbx" else ".zkp"
        stem = os.path.splitext(self.name_field.GetValue().strip())[0] or "passwords"
        self.name_field.SetValue(stem + suffix)
        for control in (self.keyfile_field, self.cipher_choice, self.kdf_choice):
            control.Enable(kind == "kdbx")

    def on_browse(self, event):
        from .dialogs import choose_folder

        chosen = choose_folder(self, lang.t(
            "dialogs", "choose_a_folder_for_the_new",
            "Choose a folder for the new database"),
                               self.folder_field.GetValue())
        if chosen:
            self.folder_field.SetValue(chosen)

    def on_create_keyfile(self, event):
        make_key_file(self, self.keyfile_field)

    def on_ok(self, event):
        from .kdbx import CIPHER_CHOICES, KDF_CHOICES

        kind = self.current_kind()
        suffix = ".kdbx" if kind == "kdbx" else ".zkp"
        folder = self.folder_field.GetValue().strip() or paths.BASE_DIR
        name = self.name_field.GetValue().strip() or ("copy" + suffix)
        if not name.lower().endswith((".kdbx", ".zkp")):
            name += suffix
        if not name.lower().endswith(suffix):
            name = os.path.splitext(name)[0] + suffix
        password = self.password_field.GetValue()
        if len(password) < 8:
            wx.MessageBox(lang.t(
                "errors", "choose_a_password_of_at_least",
                "Choose a password of at least eight characters for the new "
                "copy."), "ZKeypass", wx.OK | wx.ICON_WARNING, self)
            return
        if password != self.confirm_field.GetValue():
            wx.MessageBox(lang.t(
                "errors", "the_two_passwords_do_not_match",
                "The two passwords do not match."), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        keyfile = self.keyfile_field.GetValue().strip() or None
        if keyfile and kind != "kdbx":
            wx.MessageBox(lang.t(
                "errors", "a_key_file_belongs_to_the",
                "A key file belongs to the KeePass database format."),
                          "ZKeypass", wx.OK | wx.ICON_WARNING, self)
            return
        if not os.path.isdir(folder):
            wx.MessageBox(lang.t(
                "errors", "is_not_a_folder",
                "{folder} is not a folder.",
                folder=folder), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        target = os.path.join(folder, name)
        if os.path.exists(target) and not ask_yes_no(
                self, lang.t(
                    "dialogs", "already_exists_replace_it",
                    "{target} already exists. Replace it?",
                    target=target)):
            return
        options = {}
        if kind == "kdbx":
            options["cipher"] = CIPHER_CHOICES[max(0, self.cipher_choice.GetSelection())]
            options["kdf"] = KDF_CHOICES[max(0, self.kdf_choice.GetSelection())]
        self.result = {
            "path": target,
            "kind": kind,
            "password": password,
            "keyfile": keyfile,
            "options": options,
            "attachments": self.attachments_check.GetValue(),
        }
        self.EndModal(wx.ID_OK)


class ExportDialog(wx.Dialog):
    """Write the open database out as a readable file: CSV, XML, HTML or text."""

    def __init__(self, parent, vault, current_path=""):
        super().__init__(parent, title=lang.t(
            "dialogs", "export_database",
            "Export database"), size=(640, 470))
        self.vault = vault
        self.result = None
        grid, add = labelled(self)

        self.entry_count = vault.entry_count()
        self.summary = wx.StaticText(
            self, label=lang.t(
                "dialogs", "this_database_holds_entries",
                "This database holds {entry_count} entries.",
                entry_count=self.entry_count))
        self.summary.SetName(lang.t("dialogs", "summary", "Summary"))

        self.format_choice = add(lang.t(
            "dialogs", "export_format",
            "Export format"), lambda: wx.Choice(
            self, choices=[EXPORT_LABELS[name] for name in EXPORT_LABELS]))
        self.format_choice.SetSelection(0)
        self.format_choice.SetName(lang.t(
            "dialogs", "export_format",
            "Export format"))
        self.format_choice.Bind(wx.EVT_CHOICE, self.on_format)

        stem = os.path.splitext(os.path.basename(current_path or "passwords"))[0] \
            or "passwords"
        self.name_field = add(lang.t("dialogs", "file_name", "File name"), lambda: wx.TextCtrl(
            self, value=f"{stem}-export{EXPORT_SUFFIXES['csv']}"))
        self.name_field.SetName(lang.t("dialogs", "file_name", "File name"))
        folder = paths.EXPORT_DIR
        self.folder_field = add(lang.t("dialogs", "folder", "Folder"), lambda: wx.TextCtrl(self, value=folder))
        self.folder_field.SetName(lang.t("dialogs", "folder", "Folder"))
        browse = wx.Button(self, label=lang.control_label(
            "browse_for_a_folder_2",
            "&Browse for a folder..."))
        browse.SetName(lang.t(
            "dialogs", "browse_for_a_folder",
            "Browse for a folder"))
        browse.Bind(wx.EVT_BUTTON, self.on_browse)

        self.passwords_check = add(
            lang.t("dialogs", "passwords", "Passwords"),
            lambda: wx.CheckBox(self, label=lang.control_label(
                "include_passwords_in_the_export",
                "Include &passwords in the export")))
        self.passwords_check.SetValue(True)
        self.passwords_check.SetName(lang.t(
            "dialogs", "include_passwords",
            "Include passwords"))

        self.attachments_check = add(
            lang.t("dialogs", "stored_files", "Stored files"),
            lambda: wx.CheckBox(self, label=lang.control_label(
                "also_write_out_the_stored_files",
                "Also &write out the stored files")))
        self.attachments_check.SetValue(False)
        self.attachments_check.SetName(lang.t(
            "dialogs", "write_out_stored_files",
            "Write out stored files"))
        self.attachment_folder = add(lang.t(
            "dialogs", "folder_for_stored_files",
            "Folder for stored files"), lambda: wx.TextCtrl(
            self, value=os.path.join(paths.EXPORT_DIR, "attachments")))
        self.attachment_folder.SetName(lang.t(
            "dialogs", "folder_for_stored_files",
            "Folder for stored files"))
        choose_folder = wx.Button(self, label=lang.control_label(
            "choose_the_stored_files_folder_2",
            "Choose the stored files f&older..."))
        choose_folder.SetName(lang.t(
            "dialogs", "choose_the_stored_files_folder",
            "Choose the stored files folder"))
        choose_folder.Bind(wx.EVT_BUTTON, self.on_choose_attachment_folder)

        self.warning = wx.StaticText(
            self, label=lang.t(
                "dialogs", "an_export_file_is_not_encrypted",
                "An export file is not encrypted. Delete it when you have "
                "finished with it."))
        self.warning.Wrap(560)

        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(grid, 0, wx.EXPAND | wx.ALL, 12)
        root.Add(browse, 0, wx.LEFT | wx.RIGHT, 12)
        root.Add(choose_folder, 0, wx.LEFT | wx.RIGHT | wx.TOP, 12)
        root.Add(self.warning, 0, wx.EXPAND | wx.ALL, 12)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 12)
        self.SetSizer(root)
        self.format_choice.SetFocus()
        self.Bind(wx.EVT_BUTTON, self.on_ok, id=wx.ID_OK)

    def current_kind(self):
        return list(EXPORT_LABELS)[max(0, self.format_choice.GetSelection())]

    def on_format(self, event=None):
        kind = self.current_kind()
        stem = os.path.splitext(self.name_field.GetValue().strip())[0] or "passwords"
        self.name_field.SetValue(stem + EXPORT_SUFFIXES[kind])

    def on_browse(self, event):
        from .dialogs import choose_folder

        chosen = choose_folder(self, lang.t(
            "dialogs", "choose_a_folder_for_the_export",
            "Choose a folder for the export"),
                               self.folder_field.GetValue())
        if chosen:
            self.folder_field.SetValue(chosen)

    def on_choose_attachment_folder(self, event):
        from .dialogs import choose_folder

        chosen = choose_folder(self, lang.t(
            "dialogs", "choose_a_folder_for_the_stored",
            "Choose a folder for the stored files"),
                               self.attachment_folder.GetValue())
        if chosen:
            self.attachment_folder.SetValue(chosen)

    def on_ok(self, event):
        kind = self.current_kind()
        folder = self.folder_field.GetValue().strip() or \
            paths.EXPORT_DIR
        name = self.name_field.GetValue().strip() or ("export" +
                                                      EXPORT_SUFFIXES[kind])
        if not name.lower().endswith(EXPORT_SUFFIXES[kind]):
            name = os.path.splitext(name)[0] + EXPORT_SUFFIXES[kind]
        if not os.path.isdir(folder):
            wx.MessageBox(lang.t(
                "errors", "is_not_a_folder",
                "{folder} is not a folder.",
                folder=folder), "ZKeypass",
                          wx.OK | wx.ICON_WARNING, self)
            return
        target = os.path.join(folder, name)
        if os.path.exists(target) and not ask_yes_no(
                self, lang.t(
                    "dialogs", "already_exists_replace_it",
                    "{target} already exists. Replace it?",
                    target=target)):
            return
        attachments_folder = None
        if self.attachments_check.GetValue():
            attachments_folder = self.attachment_folder.GetValue().strip() or \
                os.path.join(folder, "attachments")
        if self.passwords_check.GetValue() and not ask_yes_no(
                self, lang.t(
                    "dialogs", "the_export_will_contain_your_passwords",
                    "The export will contain your passwords in the clear.\n\n"
                    "Anyone who opens the file can read them. Continue?")):
            return
        self.result = {"path": target, "kind": kind,
                       "passwords": self.passwords_check.GetValue(),
                       "attachments_folder": attachments_folder}
        self.EndModal(wx.ID_OK)
