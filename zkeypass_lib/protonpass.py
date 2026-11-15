"""Read a Proton Pass export.

Proton Pass exports a ZIP holding `Proton Pass/data.json` (plus any
attachments).  That JSON is read here and brought into the open database as
new entries.  Proton Pass can also write a **PGP-encrypted** `.pgp` export;
ZKeypass does not carry an OpenPGP engine, so for that file it points the person
at the plain JSON instead (Proton saves a decrypted copy beside the `.pgp`
when you export, or `gpg --decrypt file.pgp > data.json` produces one).

The JSON nests vaults, then items.  Each item has a `data` object with a
`type` ("login", "note", "creditCard", "alias"…), a `metadata` ("name",
"note") and a `content`.  A login's content holds the password, the TOTP URI
and a list of web addresses; the user name is `username`, or, in newer
exports, `itemEmail` and `itemUsername`.  Items in the trash (`state` 2) are
skipped, and the vault name becomes the group.
"""

import json
import zipfile

from . import totp
from . import lang


class ProtonPassError(Exception):
    """A Proton Pass export that could not be read, in plain English."""


def _totp_secret(value):
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _load(path):
    """The export's data.json, whether path is the ZIP or the JSON itself."""
    lowered = path.lower()
    if lowered.endswith(".pgp") or lowered.endswith(".gpg"):
        raise ProtonPassError(
            lang.t(
                "errors", "this_is_a_pgp_encrypted_proton",
                "This is a PGP-encrypted Proton Pass export, which ZKeypass "
                "cannot decrypt. In Proton Pass, export again without "
                "encryption, or open the decrypted copy Proton saves beside "
                "this file, and import that ZIP or JSON instead."))
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            member = next((name for name in archive.namelist()
                           if name.endswith("data.json")), None)
            if member is None:
                raise ProtonPassError(lang.t(
                    "errors", "this_zip_does_not_contain_a_2",
                    "This ZIP does not contain a Proton Pass data.json file."))
            with archive.open(member) as handle:
                return json.load(handle)
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        return json.load(handle)


def _username(content):
    if content.get("username"):
        return content["username"]
    email = content.get("itemEmail", "") or ""
    user = content.get("itemUsername", "") or ""
    if email and user:
        return f"{user} <{email}>"
    return user or email


def _entry(item, vault_name):
    data = item.get("data") or {}
    metadata = data.get("metadata") or {}
    content = data.get("content") or {}

    urls = content.get("urls") or []
    url = urls[0] if urls and isinstance(urls[0], str) else ""

    notes = metadata.get("note", "") or ""
    if len(urls) > 1:
        notes = (notes + "\n\n" if notes else "") + "\n".join(
            lang.t("dialogs", "also_2", "Also: {extra}", extra=extra) for extra in urls[1:] if isinstance(extra, str))

    return {
        "title": metadata.get("name", "") or lang.t(
            "dialogs", "imported_entry",
            "(imported entry)"),
        "username": _username(content),
        "password": content.get("password", "") or "",
        "url": url,
        "notes": notes,
        "totp_secret": _totp_secret(content.get("totpUri")),
        "group_name": vault_name,
    }


def parse(path):
    """Return entry dictionaries from the Proton Pass export at path."""
    data = _load(path)
    if not isinstance(data, dict) or "vaults" not in data:
        raise ProtonPassError(lang.t(
            "errors", "this_file_is_not_a_proton",
            "This file is not a Proton Pass export."))

    entries = []
    for vault in data.get("vaults", {}).values():
        vault_name = (vault or {}).get("name", "") or ""
        for item in (vault or {}).get("items", []) or []:
            if item.get("state") == 2:  # 2 is the trash
                continue
            entries.append(_entry(item, vault_name))
    return entries
