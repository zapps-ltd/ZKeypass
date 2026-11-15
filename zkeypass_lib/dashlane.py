"""Read a Dashlane JSON export.

Dashlane's "Unsecured Archive in JSON" is a ZIP holding a JSON file (or the
JSON on its own).  It is read here and brought into the open database.  The
archive is "unsecured" because Dashlane writes it in the clear; the encrypted
`.dash` archive uses an unpublished format, so that one is not supported, and
Dashlane's CSV export imports through the CSV importer instead.

The JSON groups records by kind.  `AUTHENTIFIANT` holds logins (title, domain,
login, email, password, note and sometimes an otpSecret); `SECURENOTE` holds
secure notes (title and content).  Both come across; other kinds are ignored.
"""

import json
import zipfile

from . import totp
from . import lang


class DashlaneError(Exception):
    """A Dashlane export that could not be read, in plain English."""


def _totp_secret(value):
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _load(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            member = next((name for name in archive.namelist()
                           if name.lower().endswith(".json")), None)
            if member is None:
                raise DashlaneError(lang.t(
                    "errors", "this_zip_does_not_contain_a",
                    "This ZIP does not contain a Dashlane JSON file."))
            with archive.open(member) as handle:
                return json.load(handle)
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        return json.load(handle)


def _login(item):
    username = item.get("login") or item.get("email") or ""
    secondary = item.get("secondaryLogin") or ""
    notes = item.get("note", "") or ""
    if secondary and secondary != username:
        notes = (notes + "\n" if notes else "") + lang.t(
            "dialogs", "also",
            "Also: {secondary}",
            secondary=secondary)
    return {
        "title": item.get("title", "") or item.get("domain", "")
                 or lang.t("dialogs", "imported_entry", "(imported entry)"),
        "username": username,
        "password": item.get("password", "") or "",
        "url": item.get("domain", "") or "",
        "notes": notes,
        "totp_secret": _totp_secret(item.get("otpSecret")),
        "group_name": item.get("category", "") or "",
    }


def _note(item):
    return {
        "title": item.get("title", "") or lang.t(
            "dialogs", "imported_note",
            "(imported note)"),
        "username": "", "password": "", "url": "",
        "notes": item.get("content", "") or "",
        "totp_secret": "", "group_name": item.get("category", "") or "",
    }


def parse(path):
    """Return entry dictionaries from the Dashlane JSON export at path."""
    try:
        data = _load(path)
    except json.JSONDecodeError:
        raise DashlaneError(lang.t(
            "errors", "this_file_is_not_a_dashlane",
            "This file is not a Dashlane JSON export."))
    if not isinstance(data, dict) or not ({"AUTHENTIFIANT", "SECURENOTE"}
                                          & set(data)):
        raise DashlaneError(lang.t(
            "errors", "this_file_is_not_a_dashlane",
            "This file is not a Dashlane JSON export."))

    entries = [_login(item) for item in data.get("AUTHENTIFIANT", []) or []]
    entries += [_note(item) for item in data.get("SECURENOTE", []) or []]
    return entries
