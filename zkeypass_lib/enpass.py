"""Read an Enpass 6 JSON export.

Enpass can save a SQLCipher database, which needs a native SQLCipher build
ZKeypass does not carry, or a plain JSON export (Menu > File > Export > As
JSON).  The JSON export is read here and brought into the open database.

The JSON has `folders` (each a uuid, title and parent) and `items`.  Each item
has a title, a note, a category, the folders it is in, and a list of `fields`,
each with a `type` ("username", "email", "password", "url", "totp", "section"
and so on) and a value.  The fields drive the mapping, so an entry's user name
and password come from the fields marked as such, whatever their label.
"""

import json

from . import totp
from . import lang


class EnpassError(Exception):
    """An Enpass export that could not be read, in plain English."""


def _totp_secret(value):
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _folder_paths(folders):
    """uuid -> full "parent/child" title, following parent_uuid links."""
    by_uuid = {f.get("uuid"): f for f in folders}
    paths = {}
    for uuid, folder in by_uuid.items():
        names = []
        seen = set()
        current = folder
        while current and current.get("uuid") not in seen:
            seen.add(current.get("uuid"))
            if current.get("title"):
                names.insert(0, current["title"])
            current = by_uuid.get(current.get("parent_uuid"))
        paths[uuid] = "/".join(names)
    return paths


def _entry(item, folder_paths):
    record = {"title": item.get("title", "") or lang.t(
        "dialogs", "imported_entry",
        "(imported entry)"),
              "username": "", "password": "", "url": "",
              "notes": item.get("note", "") or "", "totp_secret": "",
              "group_name": ""}
    folders = item.get("folders") or []
    if folders:
        record["group_name"] = folder_paths.get(folders[0], "")

    email = ""
    extra = []
    for field in item.get("fields", []) or []:
        field_type = (field.get("type") or "").lower()
        value = field.get("value", "") or ""
        if field_type == "section" or not value:
            continue
        if field_type == "username" and not record["username"]:
            record["username"] = value
        elif field_type == "email" and not email:
            email = value
        elif field_type == "password" and not record["password"]:
            record["password"] = value
        elif field_type in ("url", "website") and not record["url"]:
            record["url"] = value
        elif field_type == "totp" and not record["totp_secret"]:
            record["totp_secret"] = _totp_secret(value)
        else:
            extra.append(f"{field.get('label', '') or field_type}: {value}")

    if email:
        if not record["username"]:
            record["username"] = email
        else:
            extra.insert(0, f"E-mail: {email}")
    if extra:
        record["notes"] = (record["notes"] + "\n\n" if record["notes"]
                           else "") + "\n".join(extra)
    return record


def parse(path):
    """Return entry dictionaries from the Enpass JSON export at path."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError:
            raise EnpassError(lang.t(
                "errors", "this_file_is_not_an_enpass",
                "This file is not an Enpass JSON export."))
    if not isinstance(data, dict) or "items" not in data:
        raise EnpassError(lang.t(
            "errors", "this_file_is_not_an_enpass",
            "This file is not an Enpass JSON export."))

    folder_paths = _folder_paths(data.get("folders", []) or [])
    return [_entry(item, folder_paths) for item in data.get("items", []) or []]
