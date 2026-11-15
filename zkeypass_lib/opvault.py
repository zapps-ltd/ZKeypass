"""Read a 1Password OPVault folder (1Password 4 to 7).

An OPVault is a folder, not a single file: a `default` sub-folder holding
`profile.js`, `folders.js` and `band_*.js`.  Each `.js` file is JavaScript
wrapping one JSON object (`var profile={...};`, `loadFolders({...});`,
`ld({...});`); the JSON is pulled out between its first and last brace.  The
vault is read and its entries are brought into the open database; ZKeypass does
not write OPVault.

Keys, from the design 1Password published:

    derived           PBKDF2-HMAC-SHA512(password, salt, iterations) -> 64
                      bytes: encryption key, then MAC key
    master / overview each an "opdata01" blob in profile.js, decrypted with
                      the derived keys; SHA-512 of the result splits into that
                      level's own encryption and MAC keys
    item key          each item's "k" is a raw IV, AES-256-CBC ciphertext and
                      HMAC, decrypted with the master keys into the item's own
                      encryption and MAC keys

An "opdata01" blob is the tag, an 8-byte plaintext length, a 16-byte IV, the
AES-256-CBC ciphertext and a trailing HMAC-SHA256 over everything before it;
the plaintext is the last `length` bytes, the rest being random padding.  An
item's overview and details are each such a blob.
"""

import base64
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import totp
from . import lang


class OPVaultError(Exception):
    """An OPVault that could not be read, with a plain-English reason."""


def _read_js(path):
    """The JSON object inside a 1Password `.js` file."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise OPVaultError(lang.t(
            "errors", "is_not_in_the_expected_format",
            "{basename} is not in the expected format.",
            basename=os.path.basename(path)))
    return json.loads(text[start:end + 1])


def _decrypt_opdata(blob, enc_key, mac_key):
    """Decrypt and verify one opdata01 blob; return the plaintext bytes."""
    if len(blob) < 8 + 8 + 16 + 32 or blob[:8] != b"opdata01":
        raise OPVaultError(lang.t(
            "errors", "that_password_did_not_unlock_the_3",
            "That password did not unlock the vault, or it is damaged."))
    length = struct.unpack_from("<Q", blob, 8)[0]
    iv = blob[16:32]
    ciphertext = blob[32:-32]
    stored_mac = blob[-32:]
    check = hmac.new(mac_key, blob[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(check, stored_mac):
        raise OPVaultError(lang.t(
            "errors", "that_password_did_not_unlock_the_4",
            "That password did not unlock the vault. Check it and try again."))
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    return plain[len(plain) - length:] if length else b""


def _item_keys(raw_key, master_enc, master_mac):
    """Decrypt one item's "k": a raw IV, ciphertext and HMAC (no opdata tag)."""
    iv = raw_key[:16]
    ciphertext = raw_key[16:-32]
    stored_mac = raw_key[-32:]
    check = hmac.new(master_mac, raw_key[:-32], hashlib.sha256).digest()
    if not hmac.compare_digest(check, stored_mac):
        raise OPVaultError(lang.t(
            "errors", "the_vault_is_damaged_an_item",
            "The vault is damaged: an item key failed its check."))
    decryptor = Cipher(algorithms.AES(master_enc), modes.CBC(iv)).decryptor()
    keys = decryptor.update(ciphertext) + decryptor.finalize()
    return keys[:32], keys[32:64]


def _find_default(path):
    """The `default` folder, given the vault folder or something above it."""
    for candidate in (os.path.join(path, "default"),
                      os.path.join(path, "onepassword_data", "default"),
                      path):
        if os.path.isfile(os.path.join(candidate, "profile.js")):
            return candidate
    raise OPVaultError(lang.t(
        "errors", "no_profile_js_was_found_this",
        "No profile.js was found; this is not an OPVault folder."))


def _totp_secret(value):
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _entry(overview, details, folder_name):
    title = overview.get("title", "") or lang.t(
        "dialogs", "imported_entry",
        "(imported entry)")
    url = overview.get("url", "") or ""
    if not url:
        for item in overview.get("URLs", []) or []:
            if isinstance(item, dict) and item.get("u"):
                url = item["u"]
                break

    username = password = ""
    for field in details.get("fields", []) or []:
        designation = (field.get("designation") or "").lower()
        if designation == "username" and not username:
            username = field.get("value", "") or ""
        elif designation == "password" and not password:
            password = field.get("value", "") or ""
    if not password and details.get("password"):
        password = details["password"]

    notes = details.get("notesPlain", "") or ""
    secret = ""
    extra = []
    for section in details.get("sections", []) or []:
        for field in section.get("fields", []) or []:
            name = (field.get("n") or "")
            value = field.get("v")
            if (name.startswith("TOTP_") or field.get("t") == "one-time password") \
                    and not secret and isinstance(value, str):
                secret = _totp_secret(value)
                continue
            if isinstance(value, str) and value:
                label = field.get("t") or name
                extra.append(f"{label}: {value}" if label else value)
    if extra:
        notes = (notes + "\n\n" if notes else "") + "\n".join(extra)

    return {"title": title, "username": username, "password": password,
            "url": url, "notes": notes, "totp_secret": secret,
            "group_name": folder_name}


def parse(path, password):
    """Return entry dictionaries from the OPVault folder at path."""
    default = _find_default(path)
    profile = _read_js(os.path.join(default, "profile.js"))

    salt = base64.b64decode(profile["salt"])
    iterations = int(profile.get("iterations", 50000) or 50000)
    derived = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt,
                                  iterations, 64)
    derived_enc, derived_mac = derived[:32], derived[32:64]

    master = _decrypt_opdata(base64.b64decode(profile["masterKey"]),
                             derived_enc, derived_mac)
    master_hash = hashlib.sha512(master).digest()
    master_enc, master_mac = master_hash[:32], master_hash[32:64]

    overview_raw = _decrypt_opdata(base64.b64decode(profile["overviewKey"]),
                                   derived_enc, derived_mac)
    overview_hash = hashlib.sha512(overview_raw).digest()
    overview_enc, overview_mac = overview_hash[:32], overview_hash[32:64]

    folders = _folder_names(default, overview_enc, overview_mac)

    entries = []
    for name in sorted(os.listdir(default)):
        if not (name.startswith("band_") and name.endswith(".js")):
            continue
        band = _read_js(os.path.join(default, name))
        for item in band.values():
            if item.get("trashed"):
                continue
            try:
                item_enc, item_mac = _item_keys(
                    base64.b64decode(item["k"]), master_enc, master_mac)
                overview = json.loads(_decrypt_opdata(
                    base64.b64decode(item["o"]), overview_enc, overview_mac))
                details = json.loads(_decrypt_opdata(
                    base64.b64decode(item["d"]), item_enc, item_mac))
            except (KeyError, ValueError, OPVaultError):
                # A single unreadable item should not stop the whole import.
                continue
            folder_name = folders.get(item.get("folder"), "")
            entries.append(_entry(overview, details, folder_name))
    return entries


def _folder_names(default, overview_enc, overview_mac):
    """Map each folder uuid to its name, from folders.js if it is present."""
    names = {}
    path = os.path.join(default, "folders.js")
    if not os.path.isfile(path):
        return names
    try:
        folders = _read_js(path)
    except OPVaultError:
        return names
    for uuid, folder in folders.items():
        try:
            overview = json.loads(_decrypt_opdata(
                base64.b64decode(folder["overview"]), overview_enc, overview_mac))
            names[uuid] = overview.get("title", "") or ""
        except (KeyError, ValueError, OPVaultError):
            continue
    return names
