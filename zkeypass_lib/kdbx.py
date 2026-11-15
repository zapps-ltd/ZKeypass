"""KeePass 2 (KDBX) reading and writing.

Implements the parts of the KDBX 3.1 and KDBX 4 formats needed to open and
save databases that KeePassXC, KeePass 2 and other compatible programs
understand:

  * header fields, variant maps and the inner header
  * AES-KDF, Argon2d and Argon2id key derivation
  * AES-256-CBC, Twofish-256-CBC and ChaCha20 outer encryption
  * the HMAC block stream of KDBX 4 and the start bytes of KDBX 3
  * gzip compression
  * Salsa20 and ChaCha20 protected-value streams
  * the XML payload, mapped to a plain dictionary model

Only the standard library and the bundled 'cryptography' package are used.
Salsa20 and ChaCha20 keystreams are implemented here because the KeePass
inner stream uses the original 12-byte-nonce ChaCha20, which the AES-GCM
style AEAD in 'cryptography' cannot produce.

The model passed to and returned from these functions is deliberately plain:

    group = {"uuid": bytes, "name": str, "notes": str, "icon": int,
             "times": {name: datetime}, "expanded": bool,
             "custom_data": {key: str}, "entries": [entry],
             "groups": [group]}

    entry = {"uuid": bytes, "icon": int, "tags": str,
             "times": {name: datetime},
             "fields": [[key, value, protected], ...],
             "binaries": {name: bytes}, "custom_data": {key: str},
             "autotype": {...}, "history": [entry]}

    meta = {"name": str, "description": str, "default_username": str,
            "generator": str, "history_max_items": int,
            "history_max_size": int, "custom_data": {key: str}}
"""

import base64
import gzip
import hashlib
import hmac as hmaclib
import os
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2d, Argon2id
from . import lang

# --------------------------------------------------------------------- basics

SIG1 = 0x9AA2D903
SIG2 = 0xB54BFB67

VERSION_3 = 0x00030001
VERSION_4 = 0x00040000

CIPHER_AES128 = bytes.fromhex("61ab05a1946441c38d743a563df8dd35")
CIPHER_AES256 = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
CIPHER_TWOFISH = bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c")
CIPHER_CHACHA20 = bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a")

KDF_AES_KDBX3 = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")
KDF_AES_KDBX4 = bytes.fromhex("7c02bb8279a74ac0927d114a00648238")
KDF_ARGON2D = bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
KDF_ARGON2ID = bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6")

SALSA20_IV = b"\xe8\x30\x09\x4b\x97\x20\x5d\x2a"

# ------------------------------------------------------- selectable settings

# The encryption cipher and the key derivation function can both be chosen
# when a database is created, and whatever a database uses is remembered when
# it is opened so that saving keeps the original cryptography intact.

CIPHER_CHOICES = ("aes256", "chacha20", "twofish", "aes128")
CIPHER_LABELS = lang.Labels("dialogs", "kdbx_cipher_", {
    "aes256": "AES-256, CBC, the KeePass default",
    "chacha20": "ChaCha20, stream cipher",
    "twofish": "Twofish-256, CBC, as KeePassXC offers it",
    "aes128": "AES-128 (KeePass 1 era only)",
})
CIPHER_IDS = {
    "aes256": CIPHER_AES256,
    "chacha20": CIPHER_CHACHA20,
    "twofish": CIPHER_TWOFISH,
    "aes128": CIPHER_AES128,
}
CIPHER_NAMES = {
    CIPHER_AES256: "aes256",
    CIPHER_CHACHA20: "chacha20",
    CIPHER_AES128: "aes128",
    CIPHER_TWOFISH: "twofish",
}
CIPHER_IV_LENGTHS = {"aes256": 16, "aes128": 16, "chacha20": 12, "twofish": 16}

KDF_CHOICES = ("argon2id", "argon2d", "aeskdf")
KDF_LABELS = lang.Labels("dialogs", "kdbx_kdf_", {
    "argon2id": "Argon2id, memory hard, recommended",
    "argon2d": "Argon2d, memory hard, older KeePass",
    "aeskdf": "AES-KDF, repeated AES on the composite key",
})
KDF_IDS = {
    "argon2id": KDF_ARGON2ID,
    "argon2d": KDF_ARGON2D,
    "aeskdf": KDF_AES_KDBX4,
}
KDF_NAMES = {
    KDF_ARGON2ID: "argon2id",
    KDF_ARGON2D: "argon2d",
    KDF_AES_KDBX4: "aeskdf",
    KDF_AES_KDBX3: "aeskdf",
}


ZERO_UUID = b"\x00" * 16

FIELD_END = 0
FIELD_CIPHER = 2
FIELD_COMPRESSION = 3
FIELD_MASTER_SEED = 4
FIELD_TRANSFORM_SEED = 5
FIELD_TRANSFORM_ROUNDS = 6
FIELD_ENCRYPTION_IV = 7
FIELD_PROTECTED_STREAM_KEY = 8
FIELD_STREAM_START_BYTES = 9
FIELD_INNER_STREAM_ID = 10
FIELD_KDF_PARAMETERS = 11
FIELD_PUBLIC_CUSTOM_DATA = 12

INNER_END = 0
INNER_STREAM_ID = 1
INNER_STREAM_KEY = 2
INNER_BINARY = 3

VT_END = 0x00
VT_UINT32 = 0x04
VT_UINT64 = 0x05
VT_BOOL = 0x08
VT_INT32 = 0x0C
VT_INT64 = 0x0D
VT_STRING = 0x18
VT_BYTES = 0x42

BLOCK_SIZE = 1024 * 1024
M32 = 0xFFFFFFFF

EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

ENTRY_FIELD_ORDER = ("Title", "UserName", "Password", "URL", "Notes")


class KdbxError(Exception):
    """Raised with a message meant to be shown to the user."""


# ------------------------------------------------------- ChaCha20 / Salsa20


def _rotl(value, count):
    return ((value << count) | (value >> (32 - count))) & M32


def chacha20_block(key, counter, nonce):
    """One 64 byte ChaCha20 (RFC 7539) block."""
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter & M32]
    state += list(struct.unpack("<3I", nonce))
    work = state[:]

    def quarter(a, b, c, d):
        work[a] = (work[a] + work[b]) & M32
        work[d] = _rotl(work[d] ^ work[a], 16)
        work[c] = (work[c] + work[d]) & M32
        work[b] = _rotl(work[b] ^ work[c], 12)
        work[a] = (work[a] + work[b]) & M32
        work[d] = _rotl(work[d] ^ work[a], 8)
        work[c] = (work[c] + work[d]) & M32
        work[b] = _rotl(work[b] ^ work[c], 7)

    for _ in range(10):
        quarter(0, 4, 8, 12)
        quarter(1, 5, 9, 13)
        quarter(2, 6, 10, 14)
        quarter(3, 7, 11, 15)
        quarter(0, 5, 10, 15)
        quarter(1, 6, 11, 12)
        quarter(2, 7, 8, 13)
        quarter(3, 4, 9, 14)

    out = [(work[i] + state[i]) & M32 for i in range(16)]
    return struct.pack("<16I", *out)


def salsa20_block(key, counter, nonce8):
    """One 64 byte Salsa20 block, 8 byte nonce and 64 bit counter."""
    sigma = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<2I", nonce8))
    state = [sigma[0], key_words[0], key_words[1], key_words[2],
             key_words[3], sigma[1], nonce_words[0], nonce_words[1],
             counter & M32, (counter >> 32) & M32, sigma[2], key_words[4],
             key_words[5], key_words[6], key_words[7], sigma[3]]
    work = state[:]

    def quarter(a, b, c, d):
        work[b] ^= _rotl((work[a] + work[d]) & M32, 7)
        work[c] ^= _rotl((work[b] + work[a]) & M32, 9)
        work[d] ^= _rotl((work[c] + work[b]) & M32, 13)
        work[a] ^= _rotl((work[d] + work[c]) & M32, 18)

    for _ in range(10):
        quarter(0, 4, 8, 12)
        quarter(5, 9, 13, 1)
        quarter(10, 14, 2, 6)
        quarter(15, 3, 7, 11)
        quarter(0, 1, 2, 3)
        quarter(5, 6, 7, 4)
        quarter(10, 11, 8, 9)
        quarter(15, 12, 13, 14)

    out = [(work[i] + state[i]) & M32 for i in range(16)]
    return struct.pack("<16I", *out)


class XorStream:
    """XORs data with a keystream generated on demand."""

    def __init__(self, block_function, key, nonce):
        self.block_function = block_function
        self.key = key
        self.nonce = nonce
        self.counter = 0
        self.buffer = b""

    def xor(self, data):
        needle = len(data)
        while len(self.buffer) < needle:
            self.buffer += self.block_function(self.key, self.counter, self.nonce)
            self.counter += 1
        chunk = self.buffer[:needle]
        self.buffer = self.buffer[needle:]
        return bytes(a ^ b for a, b in zip(data, chunk))


def protected_stream(stream_id, key):
    """Build the inner (protected value) stream for a KDBX database."""
    if stream_id == 2:  # Salsa20
        return XorStream(salsa20_block, hashlib.sha256(key).digest(), SALSA20_IV)
    if stream_id == 3:  # ChaCha20
        derived = hashlib.sha512(key).digest()
        return XorStream(chacha20_block, derived[:32], derived[32:44])
    raise KdbxError(lang.t(
        "errors", "unsupported_inner_random_stream_cipher",
        "Unsupported inner random stream cipher ({stream_id}).",
        stream_id=stream_id))


def chacha20_stream(key, nonce):
    """Raw ChaCha20 used as the outer cipher for ChaCha20 databases."""
    return XorStream(chacha20_block, key, nonce)


# ------------------------------------------------------------- key derivation


def aes_kdf(composite_key, seed, rounds):
    encryptor = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    block = composite_key
    for _ in range(int(rounds)):
        block = encryptor.update(block)
    return hashlib.sha256(block).digest()


def _variant_int(params, name, default=0):
    value = params.get(name, default)
    return int(value) if not isinstance(value, bytes) else default


def transform_key(composite_key, kdf_parameters):
    """Turn the composite key into the transformed database key."""
    uuid = kdf_parameters.get("$UUID") or b""
    if uuid in (KDF_AES_KDBX3, KDF_AES_KDBX4):
        seed = kdf_parameters.get("S") or b""
        rounds = _variant_int(kdf_parameters, "R", 60000)
        return aes_kdf(composite_key, seed, rounds)
    if uuid in (KDF_ARGON2D, KDF_ARGON2ID):
        salt = kdf_parameters.get("S") or b""
        # KeePass stores the Argon2 memory cost in bytes, Argon2 itself wants
        # kibibytes, so the stored value is divided down before use.
        memory_bytes = _variant_int(kdf_parameters, "M", 67108864)
        memory_kib = max(8, memory_bytes // 1024)
        iterations = _variant_int(kdf_parameters, "I", 3)
        parallelism = _variant_int(kdf_parameters, "P", 2)
        if len(salt) < 8:
            raise KdbxError(lang.t(
                "errors", "the_database_has_an_invalid_argon2",
                "The database has an invalid Argon2 salt."))
        algorithm = Argon2id if uuid == KDF_ARGON2ID else Argon2d
        kdf = algorithm(salt=salt, length=32, iterations=iterations,
                        lanes=parallelism, memory_cost=memory_kib)
        return kdf.derive(composite_key)
    raise KdbxError(lang.t(
        "errors", "unsupported_key_derivation_function_in_this",
        "Unsupported key derivation function in this database."))


def keyfile_key_from_path(path):
    """Return the 32 byte key contributed by a key file.

    KeePass uses the 32 byte value itself when the key file yields exactly 32
    bytes, and hashes the file contents otherwise.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    if not raw:
        raise KdbxError(lang.t(
            "errors", "that_key_file_is_empty",
            "That key file is empty."))
    if b"<KeyFile" in raw[:512] or raw.lstrip()[:5] == b"<?xml":
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as error:
            raise KdbxError(lang.t(
                "errors", "that_key_file_could_not_be",
                "That key file could not be read: {error}",
                error=error))
        version = (root.findtext("Meta/Version") or "").strip()
        data_element = root.find("Key/Data")
        if data_element is None:
            data_element = root.find("Data")
        if data_element is None:
            for candidate in root.iter("Data"):
                data_element = candidate
                break
        text = "".join((data_element.text or "").split()) if data_element is not None else ""
        if not text:
            raise KdbxError(lang.t(
                "errors", "that_key_file_does_not_contain",
                "That key file does not contain any key data."))
        try:
            if version.startswith("2"):
                key = bytes.fromhex(text)
            else:
                key = base64.b64decode(text)
        except Exception as error:
            raise KdbxError(lang.t(
                "errors", "that_key_file_could_not_be",
                "That key file could not be read: {error}",
                error=error))
        if len(key) == 32:
            return key
        return hashlib.sha256(key).digest()
    if len(raw) == 32:
        return raw
    return hashlib.sha256(raw).digest()


def write_key_file(path):
    """Write a KeePass 2 XML key file and return the 32 byte key inside it."""
    key = os.urandom(32)
    # KeePass puts the first four bytes of the SHA-256 digest of the key in a
    # Hash attribute on the Data element and rejects the file when it is wrong,
    # so this layout is written exactly as KeePassXC writes it.
    digest = hashlib.sha256(key).hexdigest()[:8].upper()
    groups = [key.hex().upper()[index:index + 8]
              for index in range(0, 64, 8)]
    rows = ["\t\t\t" + " ".join(groups[index:index + 4])
            for index in range(0, 8, 4)]
    text = "\n".join([
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<KeyFile>",
        "\t<Meta>",
        "\t\t<Version>2.0</Version>",
        "\t</Meta>",
        "\t<Key>",
        f'\t\t<Data Hash="{digest}">',
        *rows,
        "\t\t</Data>",
        "\t</Key>",
        "</KeyFile>",
        "",
    ])
    data = text.encode("utf-8")
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    return key


def composite_key(password, keyfile_path=None, challenge_response=None):
    """Combine the password, key file and hardware key into the master key.

    The three parts are concatenated in the order KeePass uses: the hashed
    password, the key file contribution and finally any challenge-response
    result from a hardware token.
    """
    parts = []
    if password:
        parts.append(hashlib.sha256(password.encode("utf-8")).digest())
    if keyfile_path:
        parts.append(keyfile_key_from_path(keyfile_path))
    if challenge_response:
        parts.append(challenge_response if len(challenge_response) == 32
                     else hashlib.sha256(challenge_response).digest())
    if not parts:
        raise KdbxError(lang.t(
            "errors", "a_master_password_a_key_file",
            "A master password, a key file or a hardware key is required."))
    return hashlib.sha256(b"".join(parts)).digest()


# ------------------------------------------------------------------ variant map


def read_variant_map(data, position):
    """Read a KeePass variant map, returning (values, new position)."""
    version = struct.unpack_from("<H", data, position)[0]
    position += 2
    if (version & 0xFF00) > 0x0100:
        raise KdbxError(lang.t(
            "errors", "unsupported_keepass_variant_map_version",
            "Unsupported KeePass variant map version."))
    values = {}
    while position < len(data):
        field_type = data[position]
        position += 1
        if field_type == VT_END:
            break
        name_size = struct.unpack_from("<I", data, position)[0]
        position += 4
        name = data[position:position + name_size].decode("utf-8")
        position += name_size
        value_size = struct.unpack_from("<I", data, position)[0]
        position += 4
        raw = data[position:position + value_size]
        position += value_size
        values[name] = decode_variant_value(field_type, raw)
    return values, position


def decode_variant_value(field_type, raw):
    if field_type == VT_BOOL:
        return bool(raw and raw[0])
    if field_type == VT_UINT32:
        return struct.unpack("<I", raw)[0]
    if field_type == VT_INT32:
        return struct.unpack("<i", raw)[0]
    if field_type == VT_UINT64:
        return struct.unpack("<Q", raw)[0]
    if field_type == VT_INT64:
        return struct.unpack("<q", raw)[0]
    if field_type == VT_STRING:
        return raw.decode("utf-8")
    return raw


def encode_variant_value(value):
    if isinstance(value, bool):
        return VT_BOOL, b"\x01" if value else b"\x00"
    if isinstance(value, int):
        if value < 0:
            return VT_INT64, struct.pack("<q", value)
        if value <= 0xFFFFFFFF:
            return VT_UINT32, struct.pack("<I", value)
        return VT_UINT64, struct.pack("<Q", value)
    if isinstance(value, str):
        return VT_STRING, value.encode("utf-8")
    return VT_BYTES, bytes(value)


def write_variant_map(values):
    out = bytearray(struct.pack("<H", 0x0100))
    for name, value in values.items():
        field_type, raw = encode_variant_value(value)
        name_bytes = name.encode("utf-8")
        out.append(field_type)
        out += struct.pack("<I", len(name_bytes))
        out += name_bytes
        out += struct.pack("<I", len(raw))
        out += raw
    out.append(VT_END)
    return bytes(out)


# --------------------------------------------------------------- file reading


def read_database(path, password, keyfile=None, challenge_response=None):
    """Read a KDBX file, returning (meta, root group)."""
    with open(path, "rb") as handle:
        data = handle.read()
    return read_database_bytes(data, password, keyfile, challenge_response)


def read_database_bytes(data, password, keyfile=None, challenge_response=None):
    if len(data) < 12:
        raise KdbxError(lang.t(
            "errors", "that_file_is_too_short_to",
            "That file is too short to be a KeePass database."))
    sig1, sig2, version = struct.unpack_from("<III", data, 0)
    if sig1 != SIG1 or sig2 != SIG2:
        raise KdbxError(lang.t(
            "errors", "that_file_is_not_a_keepass",
            "That file is not a KeePass 2 database."))
    composite = composite_key(password, keyfile, challenge_response)
    if (version & 0xFFFF0000) >= 0x00040000:
        return _read_v4(data, version, composite)
    if (version & 0xFFFF0000) in (0x00020000, 0x00030000):
        return _read_v3(data, version, composite)
    raise KdbxError(lang.t(
        "errors", "unsupported_keepass_database_version_0x",
        "Unsupported KeePass database version (0x{version:08X}).",
        version=version))


def read_public_header(path):
    """Read the parts of a header that are not encrypted.

    Returns a dictionary with the cipher, the key derivation parameters and
    the public custom data.  Nothing here needs the master password, which is
    what lets the program find a hardware key challenge before unlocking.
    """
    with open(path, "rb") as handle:
        data = handle.read(64 * 1024)
    if len(data) < 12:
        raise KdbxError(lang.t(
            "errors", "that_file_is_too_short_to",
            "That file is too short to be a KeePass database."))
    sig1, sig2, version = struct.unpack_from("<III", data, 0)
    if sig1 != SIG1 or sig2 != SIG2:
        raise KdbxError(lang.t(
            "errors", "that_file_is_not_a_keepass",
            "That file is not a KeePass 2 database."))
    if (version & 0xFFFF0000) < 0x00040000:
        return {"cipher": "aes256", "kdf": "aeskdf", "kdf_parameters": {},
                "public_custom_data": {}, "format_version": version}
    size_width = 4
    position = 12
    stride = 1 + size_width
    fields = {}
    while position + stride <= len(data):
        field_id = data[position]
        size = struct.unpack_from("<I", data, position + 1)[0]
        position += stride
        if field_id == FIELD_END:
            break
        fields[field_id] = data[position:position + size]
        position += size
    parameters = {}
    if FIELD_KDF_PARAMETERS in fields:
        parameters, _ = read_variant_map(fields[FIELD_KDF_PARAMETERS], 0)
    public = {}
    if FIELD_PUBLIC_CUSTOM_DATA in fields:
        try:
            public, _ = read_variant_map(fields[FIELD_PUBLIC_CUSTOM_DATA], 0)
        except Exception:
            public = {}
    cipher_name = CIPHER_NAMES.get(fields.get(FIELD_CIPHER), "aes256")
    return {
        "cipher": cipher_name,
        "kdf": KDF_NAMES.get(parameters.get("$UUID"), "unsupported"),
        "kdf_parameters": parameters,
        "public_custom_data": public,
        "format_version": version,
    }


def read_public_header_of_file(path):
    """Convenience wrapper that never raises: returns {} when unreadable."""
    try:
        return read_public_header(path)
    except (KdbxError, OSError):
        return {}


def _read_header(data, position, size_width=4):
    """Read the outer header. KDBX 3 uses 2 byte field sizes, KDBX 4 uses 4."""
    fields = {}
    # KeePass hashes and HMACs the whole header, signature bytes included,
    # so the slice returned for verification starts at the first signature.
    start = 0
    stride = 1 + size_width
    while True:
        if position + stride > len(data):
            raise KdbxError(lang.t(
                "errors", "the_database_header_ended_unexpectedly",
                "The database header ended unexpectedly."))
        field_id = data[position]
        if size_width == 2:
            size = struct.unpack_from("<H", data, position + 1)[0]
        else:
            size = struct.unpack_from("<I", data, position + 1)[0]
        position += stride
        payload = data[position:position + size]
        position += size
        if field_id == FIELD_END:
            break
        fields[field_id] = payload
    return fields, data[start:position], position


def _read_v4(data, version, composite):
    fields, header_data, position = _read_header(data, 12)
    master_seed = fields.get(FIELD_MASTER_SEED)
    iv = fields.get(FIELD_ENCRYPTION_IV)
    cipher_id = fields.get(FIELD_CIPHER)
    if not master_seed or not iv or not cipher_id:
        raise KdbxError(lang.t(
            "errors", "the_database_is_missing_required_header",
            "The database is missing required header fields."))
    compression = struct.unpack("<I", fields.get(FIELD_COMPRESSION, b"\x00\x00\x00\x00"))[0]
    kdf_parameters, _ = read_variant_map(fields[FIELD_KDF_PARAMETERS], 0)
    cipher_name = CIPHER_NAMES.get(cipher_id, "unsupported")
    kdf_name = KDF_NAMES.get(kdf_parameters.get("$UUID"), "unsupported")
    transformed = transform_key(composite, kdf_parameters)
    final_key = hashlib.sha256(master_seed + transformed).digest()
    hmac_key = hashlib.sha512(master_seed + transformed + b"\x01").digest()

    header_hash = data[position:position + 32]
    header_hmac = data[position + 32:position + 64]
    position += 64
    if len(header_hash) < 32 or len(header_hmac) < 32:
        raise KdbxError(lang.t(
            "errors", "the_database_header_checksum_is_missing",
            "The database header checksum is missing."))
    if header_hash != hashlib.sha256(header_data).digest():
        raise KdbxError(lang.t(
            "errors", "the_database_header_is_damaged",
            "The database header is damaged."))
    expected = hmaclib.new(_block_key(0xFFFFFFFFFFFFFFFF, hmac_key),
                           header_data, hashlib.sha256).digest()
    if not hmaclib.compare_digest(header_hmac, expected):
        raise KdbxError(lang.t(
            "errors", "wrong_master_password_or_key_file",
            "Wrong master password or key file, or the database file is "
            "damaged."))

    payload, _ = _read_hmac_blocks(data, position, hmac_key)
    plain = _decrypt_outer(cipher_id, final_key, iv, payload)
    if compression == 1:
        plain = gzip.decompress(plain)
    stream_id, stream_key, binaries, xml_bytes = _read_inner_header(plain)
    xor = protected_stream(stream_id, stream_key)
    meta, root = _parse_xml(xml_bytes, xor, binaries)
    meta["format_version"] = version
    meta["cipher"] = cipher_name
    meta["kdf"] = kdf_name
    meta["compression"] = compression
    meta["kdf_parameters"] = kdf_parameters
    _record_costs(meta, kdf_parameters)
    if FIELD_PUBLIC_CUSTOM_DATA in fields:
        try:
            public, _ = read_variant_map(fields[FIELD_PUBLIC_CUSTOM_DATA], 0)
            meta["public_custom_data"] = {
                key: (value.decode("utf-8", "replace")
                      if isinstance(value, bytes) else value)
                for key, value in public.items()}
        except Exception:
            meta["public_custom_data"] = {}
    return meta, root


def _record_costs(meta, kdf_parameters):
    """Remember the KDF cost settings so a save can keep them."""
    parameters = kdf_parameters or {}
    if "M" in parameters:
        meta["memory_kib"] = max(8, int(parameters.get("M") or 0) // 1024)
        meta["iterations"] = int(parameters.get("I") or 3)
        meta["parallelism"] = int(parameters.get("P") or 1)
    elif "R" in parameters:
        meta["rounds"] = int(parameters.get("R") or 600000)


def _read_v3(data, version, composite):
    fields, _header, position = _read_header(data, 12, size_width=2)
    master_seed = fields.get(FIELD_MASTER_SEED)
    transform_seed = fields.get(FIELD_TRANSFORM_SEED)
    rounds = fields.get(FIELD_TRANSFORM_ROUNDS)
    iv = fields.get(FIELD_ENCRYPTION_IV)
    cipher_id = fields.get(FIELD_CIPHER, CIPHER_AES256)
    start_bytes = fields.get(FIELD_STREAM_START_BYTES, b"")
    stream_key = fields.get(FIELD_PROTECTED_STREAM_KEY, b"")
    stream_id = struct.unpack("<I", fields.get(FIELD_INNER_STREAM_ID, b"\x02\x00\x00\x00"))[0]
    if not master_seed or not transform_seed or not rounds or not iv:
        raise KdbxError(lang.t(
            "errors", "the_database_is_missing_required_header",
            "The database is missing required header fields."))
    compression = struct.unpack("<I", fields.get(FIELD_COMPRESSION, b"\x00\x00\x00\x00"))[0]
    round_count = struct.unpack("<Q", rounds)[0]
    transformed = aes_kdf(composite, transform_seed, round_count)
    final_key = hashlib.sha256(master_seed + transformed).digest()
    plain = _decrypt_outer(cipher_id, final_key, iv, data[position:])
    if start_bytes and plain[:32] != start_bytes:
        raise KdbxError(lang.t(
            "errors", "wrong_master_password_or_key_file",
            "Wrong master password or key file, or the database file is "
            "damaged."))
    plain = plain[32:]
    plain = _read_hashed_blocks(plain)
    if compression == 1:
        plain = gzip.decompress(plain)
    xor = protected_stream(stream_id, stream_key)
    meta, root = _parse_xml(plain, xor, {})
    meta["format_version"] = version
    meta["cipher"] = CIPHER_NAMES.get(bytes(cipher_id), "aes256")
    meta["kdf"] = "aeskdf"
    meta["compression"] = compression
    return meta, root


def _read_hashed_blocks(data):
    """Undo the KeePass hashed block stream used inside KDBX 3 databases.

    Each block is a little endian index, a SHA-256 hash of the payload, the
    payload size and the payload itself.  A block of size zero ends the
    stream.
    """
    out = bytearray()
    position = 0
    while True:
        if position + 40 > len(data):
            raise KdbxError(lang.t(
                "errors", "the_database_ended_in_the_middle",
                "The database ended in the middle of a block."))
        _index = struct.unpack_from("<I", data, position)[0]
        stored = data[position + 4:position + 36]
        size = struct.unpack_from("<i", data, position + 36)[0]
        position += 40
        if size < 0 or position + size > len(data):
            raise KdbxError(lang.t(
                "errors", "the_database_contains_an_invalid_block",
                "The database contains an invalid block size."))
        block = data[position:position + size]
        position += size
        if size == 0:
            # The closing block carries no data, and KeePass writes zeros
            # rather than the hash of an empty payload, so skip the check.
            break
        if hashlib.sha256(block).digest() != stored:
            raise KdbxError(lang.t(
                "errors", "the_database_file_is_damaged_a",
                "The database file is damaged (a data block failed its "
                "checksum)."))
        out += block
    return bytes(out)


def _block_key(index, hmac_key):
    return hashlib.sha512(struct.pack("<Q", index) + hmac_key).digest()


def _read_hmac_blocks(data, position, hmac_key):
    out = bytearray()
    index = 0
    while True:
        if position + 36 > len(data):
            raise KdbxError(lang.t(
                "errors", "the_database_ended_in_the_middle",
                "The database ended in the middle of a block."))
        stored = data[position:position + 32]
        size = struct.unpack_from("<i", data, position + 32)[0]
        position += 36
        if size < 0 or position + size > len(data):
            raise KdbxError(lang.t(
                "errors", "the_database_contains_an_invalid_block",
                "The database contains an invalid block size."))
        block = data[position:position + size]
        position += size
        expected = hmaclib.new(_block_key(index, hmac_key),
                               struct.pack("<Q", index) + struct.pack("<i", size) + block,
                               hashlib.sha256).digest()
        if not hmaclib.compare_digest(stored, expected):
            raise KdbxError(lang.t(
                "errors", "the_database_file_is_damaged_a",
                "The database file is damaged (a data block failed its "
                "checksum)."))
        index += 1
        if size == 0:
            break
        out += block
    return bytes(out), position


def _decrypt_outer(cipher_id, key, iv, payload):
    if cipher_id == CIPHER_CHACHA20:
        stream = chacha20_stream(key, iv)
        return stream.xor(payload)
    if cipher_id in (CIPHER_AES256, CIPHER_AES128):
        algorithm = algorithms.AES(key) if cipher_id == CIPHER_AES256 \
            else algorithms.AES(key[:16])
        decryptor = Cipher(algorithm, modes.CBC(iv)).decryptor()
        plain = decryptor.update(payload) + decryptor.finalize()
        if cipher_id == CIPHER_AES256 and len(key) != 32:
            raise KdbxError(lang.t(
                "errors", "the_database_has_an_invalid_aes",
                "The database has an invalid AES key size."))
        return _unpad(plain)
    if cipher_id == CIPHER_TWOFISH:
        from . import twofish

        if len(key) != 32 or len(payload) % 16:
            raise KdbxError(lang.t(
                "errors", "the_twofish_database_body_is_damaged",
                "The Twofish database body is damaged."))
        return _unpad(twofish.cbc_decrypt(key, iv, payload))
    raise KdbxError(lang.t(
        "errors", "the_database_uses_an_unknown_encryption",
        "The database uses an unknown encryption cipher."))


def encrypt_outer(cipher_name, key, iv, plain):
    """Encrypt the body with the chosen cipher. Mirrors _decrypt_outer."""
    cipher_id = CIPHER_IDS.get(cipher_name)
    if cipher_id is None:
        raise KdbxError(lang.t(
            "errors", "unknown_encryption_cipher",
            "Unknown encryption cipher '{cipher_name}'.",
            cipher_name=cipher_name))
    if cipher_id == CIPHER_CHACHA20:
        return chacha20_stream(key, iv).xor(plain)
    if cipher_id == CIPHER_TWOFISH:
        from . import twofish

        return twofish.cbc_encrypt(key, iv, plain)
    if cipher_id == CIPHER_AES128:
        algorithm = algorithms.AES(key[:16])
    elif cipher_id == CIPHER_AES256:
        algorithm = algorithms.AES(key)
    else:  # pragma: no cover - guarded by CIPHER_IDS above
        raise KdbxError(lang.t(
            "errors", "unknown_encryption_cipher",
            "Unknown encryption cipher '{cipher_name}'.",
            cipher_name=cipher_name))
    encryptor = Cipher(algorithm, modes.CBC(iv)).encryptor()
    return encryptor.update(_pad(plain)) + encryptor.finalize()


def _unpad(data):
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        return data
    return data[:-pad]


def _pad(data):
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _read_inner_header(plain):
    position = 0
    stream_id = 2
    stream_key = b""
    binaries = {}
    while True:
        field_id = plain[position]
        size = struct.unpack_from("<I", plain, position + 1)[0]
        position += 5
        payload = plain[position:position + size]
        position += size
        if field_id == INNER_END:
            break
        if field_id == INNER_STREAM_ID:
            stream_id = struct.unpack("<I", payload)[0]
        elif field_id == INNER_STREAM_KEY:
            stream_key = payload
        elif field_id == INNER_BINARY:
            binaries[str(len(binaries))] = payload[1:]
    return stream_id, stream_key, binaries, plain[position:]


# ------------------------------------------------------------------ XML input


def _text(element, default=""):
    if element is None or element.text is None:
        return default
    return element.text


def _date(element, default=None):
    if element is None or not (element.text or "").strip():
        return default or datetime.now(timezone.utc)
    try:
        raw = base64.b64decode(element.text.strip())
        seconds = struct.unpack("<q", raw)[0]
        return EPOCH + timedelta(seconds=seconds)
    except Exception:
        return default or datetime.now(timezone.utc)


def _parse_times(element):
    times = {}
    if element is None:
        return times
    for name in ("LastModificationTime", "CreationTime", "LastAccessTime",
                 "ExpiryTime", "LocationChanged"):
        times[name] = _date(element.find(name))
    times["Expires"] = _text(element.find("Expires")).strip().lower() == "true"
    try:
        times["UsageCount"] = int(_text(element.find("UsageCount"), "0") or 0)
    except ValueError:
        times["UsageCount"] = 0
    return times


def _parse_custom_data(element):
    data = {}
    if element is None:
        return data
    for item in element.findall("Item"):
        data[_text(item.find("Key"))] = _text(item.find("Value"))
    return data


def _parse_xml(xml_bytes, xor, binaries):
    try:
        root_element = ET.fromstring(xml_bytes)
    except ET.ParseError as error:
        raise KdbxError(lang.t(
            "errors", "the_database_contents_could_not_be",
            "The database contents could not be read: {error}",
            error=error))

    protected = {}
    for value_element in root_element.iter("Value"):
        if value_element.get("Protected") == "True":
            raw = base64.b64decode(_text(value_element))
            protected[id(value_element)] = xor.xor(raw).decode("utf-8", "replace")

    meta_element = root_element.find("Meta")
    meta = {
        "name": _text(meta_element.find("DatabaseName")) if meta_element is not None else "",
        "description": _text(meta_element.find("DatabaseDescription")) if meta_element is not None else "",
        "default_username": _text(meta_element.find("DefaultUserName")) if meta_element is not None else "",
        "generator": _text(meta_element.find("Generator")) if meta_element is not None else "",
        "custom_data": _parse_custom_data(meta_element.find("CustomData")) if meta_element is not None else {},
    }
    for name, key in (("HistoryMaxItems", "history_max_items"),
                      ("HistoryMaxSize", "history_max_size")):
        try:
            meta[key] = int(_text(meta_element.find(name), "0") or 0)
        except (ValueError, AttributeError):
            meta[key] = 0
    if meta_element is not None and meta_element.find("Binaries") is not None:
        for binary in meta_element.findall("Binaries/Binary"):
            index = binary.get("ID", str(len(binaries)))
            try:
                raw = base64.b64decode(_text(binary))
            except Exception:
                raw = b""
            if binary.get("Compressed") == "True" and raw:
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
            binaries[index] = raw

    group_element = root_element.find("Root/Group")
    if group_element is None:
        raise KdbxError(lang.t(
            "errors", "the_database_has_no_root_group",
            "The database has no root group."))
    root = _parse_group(group_element, protected, binaries)
    return meta, root


def _parse_group(element, protected, binaries):
    group = {
        "uuid": _decode_uuid(_text(element.find("UUID"))),
        "name": _text(element.find("Name")),
        "notes": _text(element.find("Notes")),
        "icon": _int(_text(element.find("IconID"), "0")),
        "times": _parse_times(element.find("Times")),
        "expanded": _text(element.find("IsExpanded")).strip().lower() != "false",
        "custom_data": _parse_custom_data(element.find("CustomData")),
        "entries": [_parse_entry(child, protected, binaries)
                    for child in element.findall("Entry")],
        "groups": [_parse_group(child, protected, binaries)
                   for child in element.findall("Group")],
    }
    return group


def _parse_entry(element, protected, binaries, history=False):
    fields = []
    for string in element.findall("String"):
        key = _text(string.find("Key"))
        value_element = string.find("Value")
        if value_element is None:
            value = ""
        elif value_element.get("Protected") == "True":
            value = protected.get(id(value_element), "")
        else:
            value = _text(value_element)
        fields.append([key, value, value_element is not None
                       and value_element.get("Protected") == "True"])
    attachments = {}
    for binary in element.findall("Binary"):
        name = _text(binary.find("Key"))
        reference = binary.find("Value")
        index = reference.get("Ref") if reference is not None else None
        if index is not None and index in binaries:
            attachments[name] = binaries[index]
        elif reference is not None and _text(reference):
            try:
                attachments[name] = base64.b64decode(_text(reference))
            except Exception:
                pass
    autotype = None
    auto_element = element.find("AutoType")
    if auto_element is not None:
        autotype = {
            "enabled": _text(auto_element.find("Enabled"), "True").strip().lower() != "false",
            "sequence": _text(auto_element.find("DefaultSequence")),
            "associations": [[_text(item.find("Window")), _text(item.find("KeystrokeSequence"))]
                             for item in auto_element.findall("Association")],
        }
    entry = {
        "uuid": _decode_uuid(_text(element.find("UUID"))),
        "icon": _int(_text(element.find("IconID"), "0")),
        "tags": _text(element.find("Tags")),
        "times": _parse_times(element.find("Times")),
        "fields": fields,
        "binaries": attachments,
        "custom_data": _parse_custom_data(element.find("CustomData")),
        "autotype": autotype,
        "history": [],
        "override_url": _text(element.find("OverrideURL")),
        "foreground": _text(element.find("ForegroundColor")),
        "background": _text(element.find("BackgroundColor")),
    }
    if not history:
        entry["history"] = [_parse_entry(child, protected, binaries, history=True)
                            for child in element.findall("History/Entry")]
    return entry


def _int(text, default=0):
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


def _decode_uuid(text):
    if not text:
        return os.urandom(16)
    try:
        raw = base64.b64decode(text)
    except Exception:
        return os.urandom(16)
    return raw if len(raw) == 16 else os.urandom(16)


# ------------------------------------------------------------------ XML output


def _encode_uuid(value):
    if isinstance(value, str):
        try:
            value = base64.b64decode(value)
        except Exception:
            value = os.urandom(16)
    if not value or len(value) != 16:
        value = os.urandom(16)
    return base64.b64encode(value).decode("ascii")


def _encode_date(moment):
    if moment is None:
        moment = datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    seconds = int((moment - EPOCH).total_seconds())
    return base64.b64encode(struct.pack("<q", seconds)).decode("ascii")


class _XmlBuilder:
    def __init__(self, xor):
        self.xor = xor

    def string(self, parent, tag, value):
        element = ET.SubElement(parent, tag)
        if value:
            element.text = str(value)
        return element

    def date(self, parent, tag, moment):
        return self.string(parent, tag, _encode_date(moment))

    def times(self, parent, times):
        element = ET.SubElement(parent, "Times")
        times = times or {}
        self.date(element, "LastModificationTime", times.get("LastModificationTime"))
        self.date(element, "CreationTime", times.get("CreationTime"))
        self.date(element, "LastAccessTime", times.get("LastAccessTime"))
        self.date(element, "ExpiryTime", times.get("ExpiryTime"))
        self.string(element, "Expires", "True" if times.get("Expires") else "False")
        self.string(element, "UsageCount", str(times.get("UsageCount", 0) or 0))
        self.date(element, "LocationChanged", times.get("LocationChanged"))
        return element

    def custom_data(self, parent, data):
        element = ET.SubElement(parent, "CustomData")
        for key, value in (data or {}).items():
            item = ET.SubElement(element, "Item")
            self.string(item, "Key", key)
            self.string(item, "Value", value)
        return element

    def entry(self, parent, entry, in_history=False):
        """Write one entry. History entries never contain a history of their own."""
        element = ET.SubElement(parent, "Entry")
        self.string(element, "UUID", _encode_uuid(entry.get("uuid")))
        self.string(element, "IconID", str(entry.get("icon", 0) or 0))
        self.string(element, "ForegroundColor", entry.get("foreground", ""))
        self.string(element, "BackgroundColor", entry.get("background", ""))
        self.string(element, "OverrideURL", entry.get("override_url", ""))
        self.string(element, "Tags", entry.get("tags", ""))
        self.times(element, entry.get("times"))
        for key, value, protect in entry.get("fields", []):
            string = ET.SubElement(element, "String")
            self.string(string, "Key", key)
            value_element = ET.SubElement(string, "Value")
            if protect:
                value_element.set("Protected", "True")
                value = self.xor.xor(str(value).encode("utf-8"))
                value_element.text = base64.b64encode(value).decode("ascii")
            elif value:
                value_element.text = str(value)
        for name, data in (entry.get("binaries") or {}).items():
            binary = ET.SubElement(element, "Binary")
            self.string(binary, "Key", name)
            reference = ET.SubElement(binary, "Value")
            reference.set("Ref", str((entry.get("_binary_refs") or {}).get(name, 0)))
        autotype = ET.SubElement(element, "AutoType")
        settings = entry.get("autotype") or {}
        self.string(autotype, "Enabled",
                    "True" if settings.get("enabled", True) else "False")
        self.string(autotype, "DataTransferObfuscation", "0")
        self.string(autotype, "DefaultSequence", settings.get("sequence", ""))
        for window, sequence in settings.get("associations", []) or []:
            association = ET.SubElement(autotype, "Association")
            self.string(association, "Window", window)
            self.string(association, "KeystrokeSequence", sequence)
        self.custom_data(element, entry.get("custom_data"))
        if in_history:
            return element
        history = ET.SubElement(element, "History")
        for item in entry.get("history", []) or []:
            self.entry(history, item, in_history=True)
        return element

    def group(self, parent, group):
        element = ET.SubElement(parent, "Group")
        self.string(element, "UUID", _encode_uuid(group.get("uuid")))
        self.string(element, "Name", group.get("name", ""))
        self.string(element, "Notes", group.get("notes", ""))
        self.string(element, "IconID", str(group.get("icon", 48) or 48))
        self.times(element, group.get("times"))
        self.string(element, "IsExpanded",
                    "True" if group.get("expanded", True) else "False")
        self.string(element, "DefaultAutoTypeSequence", "")
        self.string(element, "EnableAutoType", "null")
        self.string(element, "EnableSearching", "null")
        self.string(element, "LastTopVisibleEntry", _encode_uuid(ZERO_UUID))
        self.custom_data(element, group.get("custom_data"))
        for entry in group.get("entries", []):
            self.entry(element, entry)
        for child in group.get("groups", []):
            self.group(element, child)
        return element


def build_xml(meta, root_group, xor, binary_refs):
    """Produce the XML payload for a database."""
    builder = _XmlBuilder(xor)
    root = ET.Element("KeePassFile")
    meta_element = ET.SubElement(root, "Meta")
    meta = meta or {}
    now = datetime.now(timezone.utc)
    builder.string(meta_element, "Generator", meta.get("generator") or "ZKeypass")
    builder.string(meta_element, "DatabaseName", meta.get("name", ""))
    builder.date(meta_element, "DatabaseNameChanged", now)
    builder.string(meta_element, "DatabaseDescription", meta.get("description", ""))
    builder.date(meta_element, "DatabaseDescriptionChanged", now)
    builder.string(meta_element, "DefaultUserName", meta.get("default_username", ""))
    builder.date(meta_element, "DefaultUserNameChanged", now)
    builder.string(meta_element, "MaintenanceHistoryDays", "365")
    builder.string(meta_element, "Color", "")
    builder.date(meta_element, "MasterKeyChanged", now)
    builder.string(meta_element, "MasterKeyChangeRec", "-1")
    builder.string(meta_element, "MasterKeyChangeForce", "-1")
    protection = ET.SubElement(meta_element, "MemoryProtection")
    builder.string(protection, "ProtectTitle", "False")
    builder.string(protection, "ProtectUserName", "False")
    builder.string(protection, "ProtectPassword", "True")
    builder.string(protection, "ProtectURL", "False")
    builder.string(protection, "ProtectNotes", "False")
    ET.SubElement(meta_element, "CustomIcons")
    builder.string(meta_element, "RecycleBinEnabled", "False")
    builder.string(meta_element, "RecycleBinUUID", _encode_uuid(ZERO_UUID))
    builder.date(meta_element, "RecycleBinChanged", now)
    builder.string(meta_element, "EntryTemplatesGroup", _encode_uuid(ZERO_UUID))
    builder.date(meta_element, "EntryTemplatesGroupChanged", now)
    builder.string(meta_element, "LastSelectedGroup", _encode_uuid(root_group.get("uuid")))
    builder.string(meta_element, "LastTopVisibleGroup", _encode_uuid(root_group.get("uuid")))
    builder.string(meta_element, "HistoryMaxItems",
                   str(meta.get("history_max_items", 10) or 10))
    builder.string(meta_element, "HistoryMaxSize",
                   str(meta.get("history_max_size", 6291456) or 6291456))
    builder.date(meta_element, "SettingsChanged", now)
    builder.custom_data(meta_element, meta.get("custom_data"))

    root_element = ET.SubElement(root, "Root")
    builder.group(root_element, root_group)
    ET.SubElement(root_element, "DeletedObjects")

    body = ET.tostring(root, encoding="utf-8")
    return (b'<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n' + body), root


# --------------------------------------------------------------- file writing


def write_database(path, meta, root_group, password, keyfile=None,
                   challenge_response=None, **options):
    """Write a KDBX 4 database safely: a temporary file, then a rename.

    Any of the options accepted by write_database_bytes may be given, for
    example cipher="chacha20" or kdf="aeskdf".
    """
    data = write_database_bytes(meta, root_group, password, keyfile,
                                challenge_response=challenge_response,
                                **options)
    # The backup copy is made by the caller, into ZKeypass's backups folder.
    # Writing another one beside the database left a trail of old copies,
    # each still opening with whatever master password it was saved with.
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    return data


def build_kdf_parameters(kdf="argon2id", iterations=5, memory_kib=65536,
                         parallelism=4, rounds=600000, salt=None):
    """Variant map for the chosen key derivation function."""
    kdf = (kdf or "argon2id").lower()
    if kdf not in KDF_IDS:
        raise KdbxError(lang.t(
            "errors", "unknown_key_derivation_function",
            "Unknown key derivation function '{kdf}'.",
            kdf=kdf))
    salt = salt or os.urandom(32)
    if kdf == "aeskdf":
        return {"$UUID": KDF_AES_KDBX4, "V": 0x13, "R": int(rounds), "S": salt}
    return {
        "$UUID": KDF_IDS[kdf],
        "V": 0x13,
        "I": int(iterations),
        # KeePass expects the Argon2 memory cost in bytes, not kibibytes.
        "M": int(memory_kib) * 1024,
        "P": int(parallelism),
        "S": salt,
    }


def write_database_bytes(meta, root_group, password, keyfile=None, cipher=None,
                         kdf=None, iterations=5, memory_kib=65536,
                         parallelism=4, rounds=600000, kdf_parameters=None,
                         compression=1, keep_kdf_salt=False,
                         challenge_response=None):
    """Serialise a database to KDBX 4 bytes.

    cipher            "aes256" (default), "chacha20" or "aes128"
    kdf               "argon2id" (default), "argon2d" or "aeskdf"
    kdf_parameters    reuse an existing variant map, which also keeps the
                      original salt and cost settings of an opened database
    keep_kdf_salt     when building fresh parameters, keep the salt already
                      present in meta["kdf_parameters"]
    """
    meta = meta or {}
    cipher = (cipher or meta.get("cipher") or "aes256").lower()
    if cipher not in CIPHER_CHOICES:
        raise KdbxError(lang.t(
            "errors", "unknown_encryption_cipher_2",
            "Unknown encryption cipher '{cipher}'.",
            cipher=cipher))
    existing = meta.get("kdf_parameters") or {}
    if kdf_parameters is None:
        if existing and kdf is None:
            # The database was read from a file, so keep its original KDF,
            # salt and cost settings untouched unless asked otherwise.
            kdf_parameters = existing
        else:
            salt = existing.get("S") if (keep_kdf_salt and existing) else None
            kdf_parameters = build_kdf_parameters(
                kdf or meta.get("kdf") or "argon2id", iterations, memory_kib,
                parallelism, rounds, salt=salt)

    composite = composite_key(password, keyfile, challenge_response)
    master_seed = os.urandom(32)
    iv = os.urandom(CIPHER_IV_LENGTHS[cipher])
    protected_stream_key = os.urandom(64)

    transformed = transform_key(composite, kdf_parameters)
    final_key = hashlib.sha256(master_seed + transformed).digest()
    hmac_key = hashlib.sha512(master_seed + transformed + b"\x01").digest()

    header = bytearray()
    header += struct.pack("<III", SIG1, SIG2, VERSION_4)
    header += _header_field(FIELD_CIPHER, CIPHER_IDS[cipher])
    header += _header_field(FIELD_COMPRESSION, struct.pack("<I", int(compression)))
    header += _header_field(FIELD_MASTER_SEED, master_seed)
    header += _header_field(FIELD_ENCRYPTION_IV, iv)
    header += _header_field(FIELD_KDF_PARAMETERS, write_variant_map(kdf_parameters))
    public_custom = meta.get("public_custom_data") or {}
    if public_custom:
        values = {}
        for name, value in public_custom.items():
            values[name] = (base64.b64decode(value)
                            if isinstance(value, str) else value)
        header += _header_field(FIELD_PUBLIC_CUSTOM_DATA, write_variant_map(values))
    header += _header_field(FIELD_END, b"\r\n\r\n")
    header = bytes(header)

    inner = bytearray()
    inner += _inner_field(INNER_STREAM_ID, struct.pack("<I", 3))
    inner += _inner_field(INNER_STREAM_KEY, protected_stream_key)

    binaries = []
    binary_refs = {}
    for entry in _walk_entries(root_group):
        entry["_binary_refs"] = {}
        for name, payload in (entry.get("binaries") or {}).items():
            binary_refs[(id(entry), name)] = len(binaries)
            entry["_binary_refs"][name] = len(binaries)
            binaries.append(payload)
    for payload in binaries:
        inner += _inner_field(INNER_BINARY, b"\x01" + payload)
    inner += _inner_field(INNER_END, b"")

    xor = protected_stream(3, protected_stream_key)
    xml, _tree = build_xml(meta, root_group, xor, binary_refs)
    xml = _strip_invalid_xml(xml)

    body = bytes(inner) + xml
    if compression == 1:
        body = gzip.compress(body, compresslevel=6)
    payload = encrypt_outer(cipher, final_key, iv, body)

    out = bytearray(header)
    out += hashlib.sha256(header).digest()
    out += hmaclib.new(_block_key(0xFFFFFFFFFFFFFFFF, hmac_key), header,
                       hashlib.sha256).digest()
    out += _write_hmac_blocks(payload, hmac_key)
    return bytes(out)


def _walk_entries(group):
    for entry in group.get("entries", []):
        yield entry
        for history in entry.get("history", []) or []:
            yield history
    for child in group.get("groups", []):
        yield from _walk_entries(child)


def _header_field(field_id, payload):
    return bytes([field_id]) + struct.pack("<I", len(payload)) + payload


def _inner_field(field_id, payload):
    return bytes([field_id]) + struct.pack("<I", len(payload)) + payload


def _write_hmac_blocks(payload, hmac_key):
    out = bytearray()
    index = 0
    for start in range(0, len(payload), BLOCK_SIZE):
        out += _write_hmac_block(payload[start:start + BLOCK_SIZE], index, hmac_key)
        index += 1
    out += _write_hmac_block(b"", index, hmac_key)
    return bytes(out)


def _write_hmac_block(block, index, hmac_key):
    digest = hmaclib.new(_block_key(index, hmac_key),
                         struct.pack("<Q", index) + struct.pack("<i", len(block)) + block,
                         hashlib.sha256).digest()
    return digest + struct.pack("<i", len(block)) + block


def _strip_invalid_xml(data):
    """KeePass strips characters that XML 1.0 cannot represent."""
    allowed = bytearray()
    for byte in data:
        if byte >= 0x20 or byte in (0x09, 0x0A, 0x0D):
            allowed.append(byte)
    return bytes(allowed)
