"""Import entries from a CSV export, for example KeePass, Bitwarden or 1Password.

Column headings are matched loosely, so most exports work without editing.
"""

import csv
import os
import time

import wx

from . import paths, totp
from . import lang

FIELD_ALIASES = {
    "title": ("title", "name", "account", "entry", "item"),
    "username": ("username", "user name", "login", "user", "login_username"),
    "password": ("password", "pass", "login_password"),
    "url": ("url", "uri", "website", "web address", "login_uri"),
    "notes": ("notes", "note", "comment", "comments", "extra"),
    "totp_secret": ("totp", "otp", "otpauth", "totp secret", "login_totp",
                    "one time password"),
    "group_name": ("group", "folder", "category", "grouping", "group name"),
}


def _match(field, header):
    lowered = header.strip().lower()
    for alias in FIELD_ALIASES[field]:
        if lowered == alias:
            return True
    return False


def parse_csv(path):
    """Return a list of entry dictionaries, mapped from whatever headings exist."""
    entries = []
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        for row in reader:
            mapped = {field: "" for field in FIELD_ALIASES}
            for header, value in row.items():
                if header is None:
                    continue
                for field in FIELD_ALIASES:
                    if _match(field, header):
                        mapped[field] = (value or "").strip()
            if not any(mapped.values()):
                continue
            entries.append(mapped)
    return entries


def _add_rows(parent, vault, rows, source_name, kind="export"):
    """Confirm, then add the mapped rows to the open database as new entries.

    Shared by every import.  rows are the plain dictionaries the parsers
    return.  Returns the number of entries added, zero if cancelled.
    """
    if not rows:
        wx.MessageBox(lang.t(
            "errors", "no_entries_could_be_read_from",
            "No entries could be read from that file."), lang.t(
            "dialogs", "import",
            "Import"),
                      wx.OK | wx.ICON_WARNING, parent)
        return 0
    if wx.MessageBox(
            lang.t(
                "errors", "import_entries_from_existing_entries_are",
                "Import {count} entries from {source_name}?\n\nExisting "
                "entries are not changed. Imported entries are added to a "
                "group named after today's date.",
                count=len(rows),
                source_name=source_name),
            lang.t("dialogs", "import", "Import"), wx.YES_NO | wx.ICON_QUESTION, parent) != wx.YES:
        return 0

    group_name = lang.t(
        "dialogs", "imported",
        "Imported {date}",
        date=time.strftime('%Y-%m-%d'))
    existing = {group["name"]: group["id"] for group in vault.groups()}
    group_id = existing.get(group_name) or vault.add_group(group_name)

    imported = 0
    for row in rows:
        secret = row.get("totp_secret") or ""
        if secret and not totp.is_valid_secret(secret):
            secret = ""
        vault.save_entry({
            "title": row.get("title") or lang.t(
                "dialogs", "imported_entry",
                "(imported entry)"),
            "username": row.get("username") or "",
            "password": row.get("password") or "",
            "url": row.get("url") or "",
            "notes": row.get("notes") or "",
            "totp_secret": secret,
            "group_id": group_id,
            "favourite": 0,
            "expires": 0,
        })
        imported += 1

    wx.MessageBox(
        lang.t(
            "errors", "imported_entries_into_the_group_check",
            "Imported {imported} entries into the group {group_name}.\n\n"
            "Check that no duplicate or unwanted records were brought "
            "across, and delete the original {kind} when you are satisfied.",
            imported=imported,
            group_name=group_name,
            kind=kind),
        lang.t("dialogs", "import_complete", "Import complete"), wx.OK | wx.ICON_INFORMATION, parent)
    return imported


def import_csv_dialog(parent, vault, start_folder=None):
    """Ask for a CSV file, then add its rows to the open database."""
    folder = start_folder or paths.BASE_DIR
    from . import filebrowser

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "choose_a_csv_export",
            "Choose a CSV export"), default_dir=folder,
        wildcard="Comma separated text (*.csv)|*.csv|All files (*.*)|*.*")
    if not path:
        return 0
    try:
        rows = parse_csv(path)
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), lang.t(
            "dialogs", "import",
            "Import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path), lang.t(
        "dialogs", "csv_export",
        "CSV export"))


def import_bitwarden_dialog(parent, vault, start_folder=None):
    """Ask for a Bitwarden JSON export, then add its entries.

    A password-protected export is unlocked with the password the person set
    when they exported it; a plain export imports straight away.
    """
    folder = start_folder or paths.BASE_DIR
    from . import bitwarden, filebrowser

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "choose_a_bitwarden_json_export",
            "Choose a Bitwarden JSON export"), default_dir=folder,
        wildcard="Bitwarden export (*.json)|*.json|All files (*.*)|*.*")
    if not path:
        return 0

    password = ""
    if bitwarden.is_encrypted(path):
        prompt = wx.PasswordEntryDialog(
            parent, lang.t(
                "dialogs", "this_bitwarden_export_is_password_protected",
                "This Bitwarden export is password protected. Enter the "
                "password that was set when it was exported."), lang.t(
                "dialogs", "bitwarden_import",
                "Bitwarden import"))
        try:
            if prompt.ShowModal() != wx.ID_OK:
                return 0
            password = prompt.GetValue()
        finally:
            prompt.Destroy()

    try:
        rows = bitwarden.parse(path, password)
    except bitwarden.BitwardenError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "bitwarden_import",
            "Bitwarden import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), lang.t(
            "dialogs", "bitwarden_import",
            "Bitwarden import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path),
                     lang.t("dialogs", "bitwarden_export", "Bitwarden export"))


def _ask_password(parent, message, caption):
    """A themed password box; returns the password, or None if cancelled."""
    prompt = wx.PasswordEntryDialog(parent, message, caption)
    try:
        return prompt.GetValue() if prompt.ShowModal() == wx.ID_OK else None
    finally:
        prompt.Destroy()


def import_keepass1_dialog(parent, vault, start_folder=None):
    """Ask for a KeePass 1.x .kdb file and its password, then add its entries."""
    folder = start_folder or paths.BASE_DIR
    from . import filebrowser, keepass1

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "choose_a_keepass_1_database",
            "Choose a KeePass 1 database"), default_dir=folder,
        wildcard="KeePass 1 database (*.kdb)|*.kdb|All files (*.*)|*.*")
    if not path:
        return 0
    password = _ask_password(
        parent, lang.t(
            "dialogs", "enter_the_master_password_for_this",
            "Enter the master password for this KeePass 1 database."),
        lang.t("dialogs", "keepass_1_import", "KeePass 1 import"))
    if password is None:
        return 0
    try:
        rows = keepass1.parse(path, password)
    except keepass1.KeePass1Error as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "keepass_1_import",
            "KeePass 1 import"), wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), lang.t(
            "dialogs", "keepass_1_import",
            "KeePass 1 import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path),
                     lang.t(
                         "dialogs", "keepass_1_database",
                         "KeePass 1 database"))


def import_pwsafe_dialog(parent, vault, start_folder=None):
    """Ask for a Password Safe .psafe3 file and its password, then add entries."""
    folder = start_folder or paths.BASE_DIR
    from . import filebrowser, pwsafe

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "choose_a_password_safe_database",
            "Choose a Password Safe database"), default_dir=folder,
        wildcard="Password Safe v3 (*.psafe3)|*.psafe3|All files (*.*)|*.*")
    if not path:
        return 0
    password = _ask_password(
        parent, lang.t(
            "dialogs", "enter_the_master_password_for_this_2",
            "Enter the master password for this Password Safe database."),
        lang.t("dialogs", "password_safe_import", "Password Safe import"))
    if password is None:
        return 0
    try:
        rows = pwsafe.parse(path, password)
    except pwsafe.PasswordSafeError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "password_safe_import",
            "Password Safe import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), lang.t(
            "dialogs", "password_safe_import",
            "Password Safe import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path),
                     lang.t(
                         "dialogs", "password_safe_database",
                         "Password Safe database"))


def import_opvault_dialog(parent, vault, start_folder=None):
    """Ask for a 1Password OPVault folder and its password, then add entries."""
    folder = start_folder or paths.BASE_DIR
    from . import dialogs, opvault

    chosen = dialogs.choose_folder(
        parent, lang.t(
            "dialogs", "choose_the_opvault_folder",
            "Choose the .opvault folder"), folder)
    if not chosen:
        return 0
    password = _ask_password(
        parent, lang.t(
            "dialogs", "enter_the_master_password_for_this_3",
            "Enter the master password for this 1Password OPVault."),
        lang.t(
            "dialogs", "1password_opvault_import",
            "1Password OPVault import"))
    if password is None:
        return 0
    try:
        rows = opvault.parse(chosen, password)
    except opvault.OPVaultError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "1password_opvault_import",
            "1Password OPVault import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_folder",
            "Could not read that folder: {error}",
            error=error),
                      lang.t(
                          "dialogs", "1password_opvault_import",
                          "1Password OPVault import"), wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(chosen.rstrip("/\\"))
                     or "OPVault", lang.t(
                         "dialogs", "opvault_folder",
                         "OPVault folder"))


def _import_export_file(parent, vault, start_folder, title, wildcard,
                        reader, reader_error, source_label):
    """Shared flow for a plain (unencrypted) export file: choose, read, add.

    reader(path) returns the rows; reader_error is the reader's own exception
    class, shown to the person as a plain message.
    """
    from . import filebrowser

    path, _kind = filebrowser.choose_file(
        parent, title=title, default_dir=start_folder or paths.BASE_DIR,
        wildcard=wildcard)
    if not path:
        return 0
    try:
        rows = reader(path)
    except reader_error as error:
        wx.MessageBox(str(error), title, wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), title,
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path), source_label)


def import_protonpass_dialog(parent, vault, start_folder=None):
    """Ask for a Proton Pass export (ZIP or JSON), then add its entries."""
    from . import protonpass

    return _import_export_file(
        parent, vault, start_folder, lang.t(
            "dialogs", "choose_a_proton_pass_export",
            "Choose a Proton Pass export"),
        "Proton Pass export (*.zip;*.json)|*.zip;*.json|All files (*.*)|*.*",
        protonpass.parse, protonpass.ProtonPassError, lang.t(
            "dialogs", "proton_pass_export",
            "Proton Pass export"))


def import_enpass_dialog(parent, vault, start_folder=None):
    """Ask for an Enpass JSON export, then add its entries."""
    from . import enpass

    return _import_export_file(
        parent, vault, start_folder, lang.t(
            "dialogs", "choose_an_enpass_json_export",
            "Choose an Enpass JSON export"),
        "Enpass export (*.json)|*.json|All files (*.*)|*.*",
        enpass.parse, enpass.EnpassError, lang.t(
            "dialogs", "enpass_export",
            "Enpass export"))


def import_dashlane_dialog(parent, vault, start_folder=None):
    """Ask for a Dashlane JSON export (ZIP or JSON), then add its entries."""
    from . import dashlane

    return _import_export_file(
        parent, vault, start_folder, lang.t(
            "dialogs", "choose_a_dashlane_json_export",
            "Choose a Dashlane JSON export"),
        "Dashlane export (*.json;*.zip)|*.json;*.zip|All files (*.*)|*.*",
        dashlane.parse, dashlane.DashlaneError, lang.t(
            "dialogs", "dashlane_export",
            "Dashlane export"))


def import_1pux_dialog(parent, vault, start_folder=None):
    """Ask for a 1Password .1pux export, then add its entries."""
    folder = start_folder or paths.BASE_DIR
    from . import filebrowser, onepux

    path, _kind = filebrowser.choose_file(
        parent, title=lang.t(
            "dialogs", "choose_a_1password_1pux_export",
            "Choose a 1Password 1PUX export"), default_dir=folder,
        wildcard="1Password export (*.1pux)|*.1pux|All files (*.*)|*.*")
    if not path:
        return 0
    try:
        rows = onepux.parse(path)
    except ValueError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "1password_import",
            "1Password import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    except OSError as error:
        wx.MessageBox(lang.t(
            "errors", "could_not_read_that_file",
            "Could not read that file: {error}",
            error=error), lang.t(
            "dialogs", "1password_import",
            "1Password import"),
                      wx.OK | wx.ICON_ERROR, parent)
        return 0
    return _add_rows(parent, vault, rows, os.path.basename(path),
                     lang.t("dialogs", "1pux_export", "1PUX export"))
