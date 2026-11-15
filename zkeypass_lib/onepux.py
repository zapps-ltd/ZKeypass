"""Read a 1Password 1PUX export.

1PUX is 1Password's own export: a ZIP holding ``export.data`` (a JSON file)
and, if there were any, the attachments under ``files/``.  It is not
encrypted, so this is a plain read.  (1Password's older OPVault is encrypted
and is a separate, later piece of work.)

The JSON nests accounts, then vaults, then items.  Each item carries an
``overview`` (title and web addresses), ``details`` (login fields, notes and
sections of extra fields), and a ``categoryUuid`` that says what kind of item
it is.  Logins (001), passwords (005) and API keys (110) map cleanly; other
kinds keep their title and whatever fields they hold go into the notes, so
nothing is silently dropped.  Everything comes back as the same plain entry
dictionaries the CSV import uses.
"""

import json
import zipfile

from . import totp
from . import lang

# categoryUuid values that carry a login-shaped password.
_LOGIN_CATEGORIES = {"001", "005", "110"}


def _totp_secret(value):
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _login_fields(details):
    """Username and password from a login item's loginFields by designation."""
    username = password = ""
    for field in details.get("loginFields", []) or []:
        designation = (field.get("designation") or "").lower()
        if designation == "username" and not username:
            username = field.get("value", "") or ""
        elif designation == "password" and not password:
            password = field.get("value", "") or ""
    return username, password


def _sections(details):
    """Return (totp_secret, extra_note_lines) from the item's sections."""
    secret = ""
    notes = []
    for section in details.get("sections", []) or []:
        for field in section.get("fields", []) or []:
            value = field.get("value") or {}
            if "totp" in value and not secret:
                secret = _totp_secret(value.get("totp"))
                continue
            text = (value.get("string") or value.get("concealed")
                    or value.get("url") or value.get("email") or "")
            title = field.get("title") or ""
            if text and title:
                notes.append(f"{title}: {text}")
            elif text:
                notes.append(text)
    return secret, notes


def _first_url(overview):
    if overview.get("url"):
        return overview["url"]
    for entry in overview.get("urls", []) or []:
        if isinstance(entry, dict) and entry.get("url"):
            return entry["url"]
    return ""


def _item_entry(item, vault_name):
    overview = item.get("overview") or {}
    details = item.get("details") or {}
    username, password = _login_fields(details)
    secret, extra = _sections(details)

    notes = details.get("notesPlain", "") or ""
    if extra:
        notes = (notes + "\n\n" if notes else "") + "\n".join(extra)

    return {
        "title": overview.get("title", "") or lang.t(
            "dialogs", "imported_entry",
            "(imported entry)"),
        "username": username,
        "password": password,
        "url": _first_url(overview),
        "notes": notes,
        "totp_secret": secret,
        "group_name": vault_name,
    }


def parse(path):
    """Return entry dictionaries from a .1pux export at path."""
    try:
        with zipfile.ZipFile(path) as archive:
            with archive.open("export.data") as handle:
                payload = json.load(handle)
    except KeyError:
        raise ValueError(lang.t(
            "errors", "this_1pux_file_has_no_export",
            "This .1pux file has no export.data inside it."))
    except (OSError, zipfile.BadZipFile):
        raise ValueError(lang.t(
            "errors", "this_file_is_not_a_readable",
            "This file is not a readable 1PUX export."))
    except json.JSONDecodeError:
        raise ValueError(lang.t(
            "errors", "the_export_data_inside_this_1pux",
            "The export.data inside this 1PUX file is not valid."))

    entries = []
    for account in payload.get("accounts", []) or []:
        for vault in account.get("vaults", []) or []:
            vault_name = (vault.get("attrs") or {}).get("name", "") or ""
            for wrapper in vault.get("items", []) or []:
                item = wrapper.get("item") or wrapper
                if (item.get("state") or "active") == "archived":
                    continue
                entries.append(_item_entry(item, vault_name))
    return entries
