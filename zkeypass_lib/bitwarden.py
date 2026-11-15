"""Read a Bitwarden (or Vaultwarden) vault export, encrypted or plain.

Bitwarden exports JSON.  The account export is plain text; the file is the
one people are told to use for a backup, so it is encrypted with a password
the person types at export time.  Both are handled here, and both return the
same plain entry dictionaries the CSV import uses, so the rest of the program
needs no change.

The password-protected format, from Bitwarden's own export code:

    {
      "encrypted": true, "passwordProtected": true,
      "salt": "<random string, used as the KDF salt bytes>",
      "kdfType": 0,            # 0 PBKDF2-SHA256, 1 Argon2id
      "kdfIterations": 600000,
      "kdfMemory": 64,         # MiB, Argon2id only
      "kdfParallelism": 4,     # Argon2id only
      "encKeyValidation_DO_NOT_EDIT": "2.iv|ciphertext|mac",
      "data": "2.iv|ciphertext|mac"
    }

The password is run through the KDF to a 32-byte key, which is stretched with
HKDF-Expand (SHA-256) into a 32-byte encryption key (info "enc") and a 32-byte
MAC key (info "mac").  Each "2.iv|ct|mac" string is AES-256-CBC with the
encryption key and an HMAC-SHA256 over iv+ciphertext with the MAC key; a
wrong password shows up as a failed HMAC.
"""

import base64
import json

from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import totp
from . import lang


class BitwardenError(Exception):
    """A Bitwarden export that could not be read, with a plain-English reason."""


def _derive_master_key(password, data):
    salt = str(data.get("salt", "")).encode("utf-8")
    kdf_type = int(data.get("kdfType", 0) or 0)
    if kdf_type == 0:
        iterations = int(data.get("kdfIterations", 600000) or 600000)
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                          iterations=iterations).derive(password.encode("utf-8"))
    if kdf_type == 1:
        try:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
        except ImportError:
            raise BitwardenError(
                lang.t(
                    "errors", "this_export_uses_argon2id_which_this",
                    "This export uses Argon2id, which this build cannot "
                    "compute. Export it from Bitwarden again with the PBKDF2 "
                    "setting, or export without a file password and import "
                    "that."))
        return Argon2id(
            salt=salt, length=32,
            iterations=int(data.get("kdfIterations", 3) or 3),
            lanes=int(data.get("kdfParallelism", 4) or 4),
            memory_cost=int(data.get("kdfMemory", 64) or 64) * 1024,
        ).derive(password.encode("utf-8"))
    raise BitwardenError(lang.t(
        "errors", "this_export_uses_a_password_hardening",
        "This export uses a password hardening method ZKeypass does not know."))


def _stretch(master_key):
    enc = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                     info=b"enc").derive(master_key)
    mac = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                     info=b"mac").derive(master_key)
    return enc, mac


def _decrypt_string(enc_string, enc_key, mac_key):
    """Decrypt one "2.iv|ciphertext|mac" value; raise on a wrong password."""
    try:
        kind, rest = enc_string.split(".", 1)
        iv_b64, ct_b64, mac_b64 = rest.split("|")
    except (ValueError, AttributeError):
        raise BitwardenError(lang.t(
            "errors", "the_export_is_not_in_the",
            "The export is not in the expected format."))
    if kind != "2":
        raise BitwardenError(lang.t(
            "errors", "this_export_uses_an_encryption_type",
            "This export uses an encryption type ZKeypass does not support."))
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ct_b64)
    expected = base64.b64decode(mac_b64)

    check = hmac.HMAC(mac_key, hashes.SHA256())
    check.update(iv + ciphertext)
    try:
        check.verify(expected)
    except Exception:
        raise BitwardenError(lang.t(
            "errors", "that_password_did_not_unlock_the",
            "That password did not unlock the export. Check it and try again."))
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def _totp_secret(value):
    """A stored secret or an otpauth link, reduced to a plain setup key."""
    value = (value or "").strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth"):
        parsed = totp.parse_otpauth(value)
        return parsed["secret"] if parsed else ""
    return value if totp.is_valid_secret(value) else ""


def _entries_from_payload(payload):
    """Map a decrypted or plain Bitwarden payload to entry dictionaries."""
    folders = {folder.get("id"): folder.get("name", "")
               for folder in payload.get("folders", []) or []}
    entries = []
    for item in payload.get("items", []) or []:
        login = item.get("login") or {}
        uris = login.get("uris") or []
        url = ""
        if uris and isinstance(uris[0], dict):
            url = uris[0].get("uri", "") or ""
        entries.append({
            "title": item.get("name", "") or lang.t(
                "dialogs", "imported_entry",
                "(imported entry)"),
            "username": login.get("username", "") or "",
            "password": login.get("password", "") or "",
            "url": url,
            "notes": item.get("notes", "") or "",
            "totp_secret": _totp_secret(login.get("totp")),
            "group_name": folders.get(item.get("folderId"), ""),
        })
    return entries


def parse(path, password=""):
    """Return entry dictionaries from a Bitwarden export at path.

    password is needed only for a password-protected export; an empty password
    for one raises BitwardenError asking for it.
    """
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError:
            raise BitwardenError(lang.t(
                "errors", "this_file_is_not_a_bitwarden",
                "This file is not a Bitwarden JSON export."))
    if not isinstance(data, dict):
        raise BitwardenError(lang.t(
            "errors", "this_file_is_not_a_bitwarden",
            "This file is not a Bitwarden JSON export."))

    if not data.get("encrypted"):
        return _entries_from_payload(data)

    if not password:
        raise BitwardenError(lang.t(
            "errors", "this_export_is_password_protected_enter",
            "This export is password protected. Enter the password that was "
            "set when it was exported."))
    master_key = _derive_master_key(password, data)
    enc_key, mac_key = _stretch(master_key)
    # Fail early, with the clear "wrong password" message, on the small
    # validation value before decrypting the whole vault.
    validation = data.get("encKeyValidation_DO_NOT_EDIT")
    if validation:
        _decrypt_string(validation, enc_key, mac_key)
    payload = json.loads(_decrypt_string(data["data"], enc_key, mac_key))
    return _entries_from_payload(payload)


def is_encrypted(path):
    """True when the export needs a password, read from its header only."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            data = json.load(handle)
        return bool(isinstance(data, dict) and data.get("encrypted"))
    except (OSError, json.JSONDecodeError):
        return False
