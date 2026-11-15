"""Read a Password Safe v3 `.psafe3` database.

Password Safe is Bruce Schneier's manager (also pwSafe on macOS and iOS).
The file is read here and brought into the open database as new entries;
ZKeypass does not write the format.  It leans on the Twofish code from phase 1.

Layout:

    "PWS3"                     tag, 4 bytes
    SALT                       32 bytes
    ITER                       key-stretch count, 4-byte little-endian
    H(P')                      SHA-256 of the stretched key, 32 bytes
    B1 B2                      the record key K, as two Twofish-ECB blocks
    B3 B4                      the HMAC key L, as two Twofish-ECB blocks
    IV                         16 bytes
    ...encrypted records...    Twofish-256-CBC, block aligned
    "PWS3-EOFPWS3-EOF"         16-byte end marker, in clear
    HMAC                       HMAC-SHA256 over the plain field data, 32 bytes

The stretched key P' is SHA-256 of the password and salt, hashed ITER more
times; SHA-256 of it must match H(P').  K and L come from decrypting B1..B4
with P'.  The decrypted stream is a run of fields, each a 4-byte length, a
one-byte type and the data, padded up to the 16-byte block; a 0xFF field ends
the header, then each record, likewise 0xFF-terminated.
"""

import hashlib
import hmac
import struct

from . import totp, twofish
from . import lang

TAG = b"PWS3"
EOF_MARKER = b"PWS3-EOFPWS3-EOF"
BLOCK = 16

# Record field types we carry across.
FIELD_GROUP = 0x02
FIELD_TITLE = 0x03
FIELD_USERNAME = 0x04
FIELD_NOTES = 0x05
FIELD_PASSWORD = 0x06
FIELD_URL = 0x0D
FIELD_EMAIL = 0x14
FIELD_TWO_FACTOR = 0x1B
FIELD_END = 0xFF


class PasswordSafeError(Exception):
    """A `.psafe3` file that could not be read, with a plain-English reason."""


def is_psafe3(path):
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == TAG
    except OSError:
        return False


def _stretch(password, salt, iterations):
    stretched = hashlib.sha256(password.encode("utf-8") + salt).digest()
    for _ in range(iterations):
        stretched = hashlib.sha256(stretched).digest()
    return stretched


def _fields(plain):
    """Yield (type, data) for every field in the decrypted stream."""
    offset = 0
    while offset + BLOCK <= len(plain):
        length, field_type = struct.unpack_from("<IB", plain, offset)
        data = bytearray(plain[offset + 5:offset + 5 + length])
        # A field is a whole number of blocks; the data may spill past the
        # first block's eleven bytes into the blocks that follow.
        used = 5 + length
        blocks = max(1, (used + BLOCK - 1) // BLOCK)
        offset += blocks * BLOCK
        yield field_type, bytes(data)


def _two_factor_secret(data):
    """A Two-Factor Key field is raw bytes; show it as a base32 setup key."""
    try:
        import base64

        secret = base64.b32encode(data).decode("ascii").rstrip("=")
        return secret if totp.is_valid_secret(secret) else ""
    except Exception:
        return ""


def parse(path, password):
    """Return entry dictionaries from the `.psafe3` file at path."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) < 152 + BLOCK + 32 or raw[:4] != TAG:
        raise PasswordSafeError(lang.t(
            "errors", "this_is_not_a_password_safe",
            "This is not a Password Safe v3 database."))

    salt = raw[4:36]
    iterations = struct.unpack_from("<I", raw, 36)[0]
    stored_hash = raw[40:72]
    b1, b2, b3, b4 = raw[72:88], raw[88:104], raw[104:120], raw[120:136]
    iv = raw[136:152]

    stretched = _stretch(password, salt, iterations)
    if hashlib.sha256(stretched).digest() != stored_hash:
        raise PasswordSafeError(lang.t(
            "errors", "that_password_did_not_unlock_the_2",
            "That password did not unlock the database. Check it and try "
            "again."))

    cipher = twofish.Twofish(stretched)
    record_key = cipher.decrypt_block(b1) + cipher.decrypt_block(b2)
    hmac_key = cipher.decrypt_block(b3) + cipher.decrypt_block(b4)

    marker = raw.find(EOF_MARKER, 152)
    if marker < 0 or (marker - 152) % BLOCK:
        raise PasswordSafeError(lang.t(
            "errors", "this_password_safe_database_is_damaged",
            "This Password Safe database is damaged."))
    body = raw[152:marker]
    stored_mac = raw[marker + BLOCK:marker + BLOCK + 32]

    plain = twofish.cbc_decrypt(record_key, iv, body)

    mac = hmac.new(hmac_key, digestmod=hashlib.sha256)
    entries = []
    current = None
    in_header = True
    for field_type, data in _fields(plain):
        mac.update(data)
        if field_type == FIELD_END:
            if in_header:
                in_header = False
            else:
                if current is not None:
                    entries.append(current)
                current = None
            continue
        if in_header:
            continue
        if current is None:
            current = {"title": "", "username": "", "password": "", "url": "",
                       "notes": "", "totp_secret": "", "group_name": ""}
        text = data.decode("utf-8", "replace")
        if field_type == FIELD_TITLE:
            current["title"] = text
        elif field_type == FIELD_USERNAME:
            current["username"] = text
        elif field_type == FIELD_PASSWORD:
            current["password"] = text
        elif field_type == FIELD_URL:
            current["url"] = text
        elif field_type == FIELD_NOTES:
            current["notes"] = text
        elif field_type == FIELD_GROUP:
            current["group_name"] = text.replace(".", "/")
        elif field_type == FIELD_EMAIL and not current.get("url"):
            current["notes"] = (current["notes"] + "\n" if current["notes"]
                                else "") + lang.t(
                                    "dialogs", "email",
                                    "Email: {text_value}",
                                    text_value=text)
        elif field_type == FIELD_TWO_FACTOR:
            current["totp_secret"] = _two_factor_secret(data)
    if current is not None:
        entries.append(current)

    if not hmac.compare_digest(mac.digest(), stored_mac):
        raise PasswordSafeError(lang.t(
            "errors", "this_password_safe_database_did_not",
            "This Password Safe database did not pass its integrity check; "
            "it may be damaged."))

    for entry in entries:
        entry["title"] = entry["title"] or lang.t(
            "dialogs", "imported_entry",
            "(imported entry)")
    return entries
