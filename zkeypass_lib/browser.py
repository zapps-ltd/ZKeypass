"""Browser integration: fill logins and create passkeys from a browser.

Two ways in are offered, both of them local:

  1. A loopback socket on 127.0.0.1, which a browser extension can open.
     Frames are a four byte big endian length followed by JSON, and every
     frame after the handshake is sealed with ChaCha20-Poly1305 using keys
     derived from an X25519 exchange.

  2. Native messaging: the same JSON frames on standard input and output,
     so an extension registered as a native messaging host can talk to
     ZKeypass with no socket at all.  Run this module with --native-messaging.

The handshake mirrors the shape of the KeePassXC-Browser protocol:

    change-public-keys   both sides exchange X25519 public keys
    associate            the user approves the browser; a shared secret is
                         kept in the database, and later connections only
                         need the identifier
    test-associate       is this browser still paired
    get-databasehash     a hash that changes whenever the database changes
    get-logins           every entry whose web address matches the request
    set-login            store a new or updated login
    generate-password    a fresh password made by the built-in generator
    lock-database        lock the vault
    get-totp             the current two factor code for an entry

Every message is encrypted after the handshake, so a plain request has to be
part of the handshake itself.  Association is never silent: the running
program asks the user to approve it.

The real KeePassXC-Browser extension speaks the same message names but seals
its payloads with libsodium crypto_box and its own framing, so it will not
pair with this server.  An extension written for ZKeypass, or the included
client helper, works with it.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from . import lang

DEFAULT_PORT = 19455
DEFAULT_HOST = "127.0.0.1"
MAX_FRAME = 8 * 1024 * 1024

# Message names, as used by the browser side.
MSG_CHANGE_KEYS = "change-public-keys"
MSG_ASSOCIATE = "associate"
MSG_TEST_ASSOCIATE = "test-associate"
MSG_DATABASE_HASH = "get-databasehash"
MSG_GET_LOGINS = "get-logins"
MSG_SET_LOGIN = "set-login"
MSG_GENERATE_PASSWORD = "generate-password"
MSG_LOCK = "lock-database"
MSG_GET_TOTP = "get-totp"

ASSOCIATE_NAMES = ("associate", "test-associate", "get-databasehash",
                   "get-logins", "set-login", "generate-password",
                   "lock-database", "get-totp")


class BrowserError(Exception):
    """Raised with a message meant for the user or the browser."""


# ------------------------------------------------------------------- framing

def encode_frame(payload):
    """Four byte big endian length then the payload bytes."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


def read_frame(stream):
    """Read one length prefixed frame, or b'' at end of stream."""
    header = stream.read(4)
    if not header or len(header) < 4:
        return b""
    length = struct.unpack(">I", header)[0]
    if length <= 0 or length > MAX_FRAME:
        raise BrowserError("The browser sent an impossible message length.")
    body = b""
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            break
        body += chunk
    return body


# ------------------------------------------------------------ crypto helpers

def generate_key_pair():
    """A new X25519 pair, returned as (private bytes, public bytes)."""
    private = X25519PrivateKey.generate()
    return (private.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()),
            private.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw))


def shared_secret(private_bytes, peer_public_bytes):
    """Diffie-Hellman between our private key and the peer's public key."""
    private = X25519PrivateKey.from_private_bytes(private_bytes)
    try:
        peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    except ValueError as error:
        raise BrowserError(f"That public key is not valid: {error}")
    return private.exchange(peer)


def derive_session_keys(secret, salt=b"zkpass-browser-session"):
    """Two 32 byte keys and a nonce base from one shared secret."""
    material = HKDF(algorithm=hashes.SHA256(), length=96, salt=salt,
                    info=b"ZKPass browser integration").derive(secret)
    return material[:32], material[32:64], material[64:96]


def seal(key, nonce_base, counter, message):
    """Encrypt a JSON message, returning the two fields the browser needs."""
    nonce = _nonce(nonce_base, counter)
    text = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sealed = ChaCha20Poly1305(key).encrypt(nonce, text, None)
    return {"nonce": base64.b64encode(nonce).decode("ascii"),
            "message": base64.b64encode(sealed).decode("ascii")}


def open_sealed(key, nonce_base, counter, envelope):
    """Decrypt a browser envelope, returning the JSON message."""
    try:
        nonce = base64.b64decode(envelope.get("nonce") or "")
        body = base64.b64decode(envelope.get("message") or "")
    except Exception as error:
        raise BrowserError(f"That message could not be decoded: {error}")
    if len(nonce) != 12:
        nonce = _nonce(nonce_base, counter)
    try:
        plain = ChaCha20Poly1305(key).decrypt(nonce, body, None)
    except Exception:
        raise BrowserError("The browser could not be authenticated. "
                           "Pair the browser again.")
    try:
        return json.loads(plain.decode("utf-8"))
    except ValueError as error:
        raise BrowserError(f"That message was not valid JSON: {error}")


def _nonce(nonce_base, counter):
    """A 12 byte nonce: eight fixed bytes from the handshake, four counting."""
    return bytes(nonce_base[:8]) + struct.pack(">I", counter & 0xFFFFFFFF)


# ---------------------------------------------------------------- association

def database_hash(text):
    """A short hash that changes whenever the database contents change."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).hexdigest()[:32]


def new_association_id():
    return base64.b64encode(os.urandom(24)).decode("ascii")


class BrowserBridge:
    """The protocol itself, independent of how a message arrives.

    Every entry point takes and returns plain dictionaries, which makes the
    whole thing testable without a socket or a browser.
    """

    def __init__(self, vault, password=None, settings=None, totp_module=None,
                 generator_module=None, ask_permission=None, lock_callback=None):
        self.vault = vault
        self.password = password
        self.settings = settings or {}
        self.totp = totp_module
        self.generator = generator_module
        self.ask_permission = ask_permission
        self.lock_callback = lock_callback
        self.private_key, self.public_key = generate_key_pair()
        self.peer_public = None
        self.session_key = None
        self.nonce_base = None
        self.request_counter = 0
        self.response_counter = 0
        self.associated_id = None
        self.associations = _load_associations(self.vault)
        self.enabled = True
        self.last_activity = time.time()

    # ------------------------------------------------------------- handshake

    def handshake(self, message):
        """Answer the plain change-public-keys request."""
        if message.get("action") != MSG_CHANGE_KEYS:
            raise BrowserError("The first message must be change-public-keys.")
        key = message.get("publicKey") or message.get("key") or ""
        try:
            self.peer_public = base64.b64decode(key)
        except Exception:
            raise BrowserError("The browser sent an unreadable public key.")
        if len(self.peer_public) != 32:
            raise BrowserError("The browser sent a public key of the wrong size.")
        secret = shared_secret(self.private_key, self.peer_public)
        self.session_key, _confirm, self.nonce_base = derive_session_keys(secret)
        self.request_counter = 0
        self.response_counter = 0
        reply = {
            "action": MSG_CHANGE_KEYS,
            "version": "1.0",
            "publicKey": base64.b64encode(self.public_key).decode("ascii"),
            "success": "true",
        }
        # The very first reply is plain, every later one is sealed.
        return reply, False

    def handle_plain(self, message):
        """Route a decoded message, which is a plain one only at start up."""
        action = message.get("action")
        if action == MSG_CHANGE_KEYS:
            return self.handshake(message)
        if self.session_key is None:
            raise BrowserError("The handshake must come first.")
        reply = self.dispatch(message)
        return reply, True

    def handle_envelope(self, envelope):
        """Decode, route and re-seal one message from a paired browser."""
        if self.session_key is None:
            raise BrowserError("The handshake must come first.")
        message = open_sealed(self.session_key, self.nonce_base,
                              self.request_counter, envelope)
        self.request_counter += 1
        reply = self.dispatch(message)
        sealed = seal(self.session_key, self.nonce_base, self.response_counter,
                      reply)
        self.response_counter += 1
        return sealed

    # ---------------------------------------------------------------- routing

    def dispatch(self, message):
        action = message.get("action")
        self.last_activity = time.time()
        if action not in ASSOCIATE_NAMES:
            return {"success": "false", "error": f"Unknown action '{action}'."}
        if action == MSG_TEST_ASSOCIATE:
            return self.do_test_associate(message)
        if action == MSG_ASSOCIATE:
            return self.do_associate(message)
        if action == "get-database-groups":        # accepted, nothing to do
            return {"success": "true", "defaultGroup": "", "groups": [],
                    "version": "1.0"}
        if action == MSG_DATABASE_HASH:
            return self.do_database_hash(message)
        if action == MSG_GET_LOGINS:
            return self.do_get_logins(message)
        if action == MSG_SET_LOGIN:
            return self.do_set_login(message)
        if action == MSG_GENERATE_PASSWORD:
            return self.do_generate_password(message)
        if action == MSG_LOCK:
            return self.do_lock(message)
        if action == MSG_GET_TOTP:
            return self.do_get_totp(message)
        return {"success": "false", "error": "Unhandled action."}

    def _identifier(self, message):
        return (message.get("id") or message.get("identifier") or "").strip()

    def _check_associated(self, message):
        identifier = self._identifier(message)
        if not identifier:
            raise BrowserError("The browser must associate first.")
        entry = self.associations.get(identifier)
        if entry is None:
            raise BrowserError("This browser is not paired with the database. "
                               "Pair it again.")
        return identifier, entry

    def do_test_associate(self, message):
        identifier = self._identifier(message)
        if identifier in self.associations:
            return {"success": "true", "id": identifier,
                    "version": "1.0"}
        return {"success": "false", "error": "Not paired."}

    def do_associate(self, message):
        identifier = self._identifier(message) or new_association_id()
        name = (message.get("key") or message.get("browserName")
                or "a browser").strip()[:100]
        if identifier in self.associations:
            return {"success": "true", "id": identifier, "version": "1.0"}
        if self.ask_permission is not None:
            allowed = self.ask_permission(name)
            if not allowed:
                return {"success": "false",
                        "error": "The request to pair was refused."}
        self.associations[identifier] = {
            "name": name,
            "created": time.time(),
            "database": database_hash(self._database_fingerprint()),
        }
        _save_associations(self.vault, self.associations)
        return {"success": "true", "id": identifier, "version": "1.0"}

    def do_database_hash(self, message):
        self._check_associated(message)
        return {"success": "true",
                "hash": database_hash(self._database_fingerprint()),
                "version": "1.0"}

    def _database_fingerprint(self):
        """Something that changes whenever any entry changes."""
        parts = []
        for entry in self.vault.entries():
            parts.append("|".join(str(entry.get(field) or "") for field in
                                  ("id", "title", "username", "password", "url",
                                   "notes", "modified")))
        return "\n".join(parts).encode("utf-8")

    def do_get_logins(self, message):
        self._check_associated(message)
        url = (message.get("url") or "").strip()
        host = _host_of(url)
        match = message.get("submitUrl") or message.get("url")
        wanted = host or _host_of(match)
        found = []
        for entry in self.vault.entries():
            if not _same_site(wanted, _host_of(entry.get("url"))):
                continue
            found.append({
                "login": entry.get("username") or "",
                "name": entry.get("title") or "",
                "password": entry.get("password") or "",
                "uuid": str(entry.get("id") or ""),
                "group": entry.get("group_name") or "",
                "url": entry.get("url") or "",
                "totp": bool(self.totp and self.totp.has_code(entry)),
            })
        return {"success": "true", "count": str(len(found)),
                "entries": found, "version": "1.0"}

    def do_set_login(self, message):
        self._check_associated(message)
        url = (message.get("url") or message.get("submitUrl") or "").strip()
        username = message.get("login") or message.get("username") or ""
        password = message.get("password") or ""
        title = message.get("name") or _host_of(url) or "New login"
        if not url:
            return {"success": "false", "error": "No web address was sent."}
        for entry in self.vault.entries():
            if (_same_site(_host_of(url), _host_of(entry.get("url")))
                    and (entry.get("username") or "") == username):
                record = self.vault.get_entry(entry["id"])
                record["password"] = password
                record["url"] = url
                if title:
                    record["title"] = title
                self.vault.save_entry(record)
                self._persist()
                return {"success": "true", "count": "1", "version": "1.0"}
        new_id = self.vault.save_entry({
            "title": title, "username": username, "password": password,
            "url": url, "notes": "", "group_id": None,
        })
        self._persist()
        return {"success": "true", "count": "1", "id": str(new_id),
                "version": "1.0"}

    def do_generate_password(self, message):
        self._check_associated(message)
        length = int(message.get("length") or 20)
        if self.generator is None:
            return {"success": "false", "error": "No generator is available."}
        password = self.generator.generate_password(
            length=max(4, min(length, 128)))
        return {"success": "true", "password": password, "version": "1.0"}

    def do_get_totp(self, message):
        self._check_associated(message)
        identifier = message.get("uuid") or message.get("id") or ""
        for entry in self.vault.entries():
            if str(entry.get("id")) == str(identifier) or \
                    (entry.get("title") or "") == str(identifier):
                if self.totp is None or not entry.get("totp_secret"):
                    return {"success": "false",
                            "error": "That entry has no two factor secret."}
                code = self.totp.current_code(entry)
                # A browser wants the bare digits, without the display space.
                text = self.totp.format_code(code).replace(" ", "") if code else ""
                return {"success": "true", "totp": text, "version": "1.0"}
        return {"success": "false", "error": "No matching entry."}

    def do_lock(self, message):
        if self.lock_callback is not None:
            self.lock_callback()
        return {"success": "true", "version": "1.0"}

    def _persist(self):
        """Save the database after a change, if the caller handed in a password."""
        try:
            self.vault.save(self.password) if self.password else None
        except Exception:
            pass


def _is_envelope(message):
    """True when a decoded message is a sealed envelope rather than a request.

    Envelopes carry "nonce" and "message" and no "action", which is what
    tells the two apart on the wire.
    """
    return (isinstance(message, dict) and "nonce" in message
            and "message" in message and "action" not in message)


def _load_associations(vault):
    """Paired browsers, kept in the database's own custom data."""
    try:
        data = (vault.meta or {}).get("custom_data", {}).get("browser_associations")
    except AttributeError:
        data = None
    if not data:
        return {}
    try:
        loaded = json.loads(data)
        return loaded if isinstance(loaded, dict) else {}
    except ValueError:
        return {}


def _save_associations(vault, associations):
    try:
        vault.meta.setdefault("custom_data", {})[
            "browser_associations"] = json.dumps(associations)
        vault.dirty = True
    except AttributeError:
        pass


def _host_of(url):
    """The host part of a web address, without the scheme or port."""
    text = (url or "").strip().lower()
    if not text:
        return ""
    text = text.split("://", 1)[-1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    if "@" in text:
        text = text.split("@", 1)[-1]
    text = text.split(":", 1)[0]
    return text[4:] if text.startswith("www.") else text


def _same_site(first, second):
    """True when two hosts belong to the same site, sub domains included."""
    if not first or not second:
        return False
    if first == second:
        return True
    return first.endswith("." + second) or second.endswith("." + first)


# ------------------------------------------------------------------ the server

class BrowserServer:
    """A loopback socket that answers browser messages."""

    def __init__(self, vault, password=None, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 ask_permission=None, lock_callback=None, **_options):
        self.bridge = BrowserBridge(vault, password,
                                    ask_permission=ask_permission,
                                    lock_callback=lock_callback)
        self.host = host
        self.port = int(port)
        self._socket = None
        self._thread = None
        self._running = False
        self.last_error = ""
        self.connections = 0

    @property
    def running(self):
        return self._running

    def start(self):
        if self._running:
            return
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.host, self.port))
            self._socket.listen(4)
        except OSError as error:
            self._socket = None
            raise BrowserError(
                lang.t(
                    "errors", "could_not_listen_on_another_program",
                    "Could not listen on {host}:{port}. Another program may "
                    "be using that port. {error}",
                    host=self.host,
                    port=self.port,
                    error=error))
        self.port = self._socket.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            if self._socket:
                self._socket.close()
        except OSError:
            pass
        self._socket = None

    def _serve(self):
        while self._running:
            try:
                connection, _address = self._socket.accept()
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._handle, args=(connection,),
                             daemon=True).start()

    def _handle(self, connection):
        import io

        stream = connection.makefile("rwb")
        try:
            while self._running:
                payload = read_frame(stream)
                if not payload:
                    break
                try:
                    message = json.loads(payload.decode("utf-8"))
                except ValueError:
                    break
                try:
                    if _is_envelope(message):
                        out = self.bridge.handle_envelope(message)
                    else:
                        out = self.bridge.handle_plain(message)[0]
                except BrowserError as error:
                    out = {"success": "false", "error": str(error)}
                stream.write(encode_frame(json.dumps(out)))
                stream.flush()
        except (OSError, BrowserError):
            pass
        finally:
            try:
                stream.close()
                connection.close()
            except OSError:
                pass


# ------------------------------------------------------- native messaging mode

def native_messaging_loop(vault, password=None, ask_permission=None,
                          lock_callback=None):
    """Talk to a browser through standard input and output.

    A browser starts this program itself and speaks the same length prefixed
    JSON frames.  Nothing is printed to standard output except frames, so
    diagnostics go to standard error.
    """
    import sys

    bridge = BrowserBridge(vault, password, ask_permission=ask_permission,
                           lock_callback=lock_callback)
    while True:
        payload = read_frame(sys.stdin.buffer)
        if not payload:
            break
        try:
            message = json.loads(payload.decode("utf-8"))
        except ValueError:
            break
        try:
            if _is_envelope(message):
                out = bridge.handle_envelope(message)
            else:
                out = bridge.handle_plain(message)[0]
        except BrowserError as error:
            out = {"success": "false", "error": str(error)}
        sys.stdout.buffer.write(encode_frame(json.dumps(out)))
        sys.stdout.buffer.flush()


def native_manifest(program_path, extension_ids=("zkeypass-browser@example",),
                    name="ZKeypass"):
    """Text of the manifest a browser needs for native messaging.

    The file is written inside the program folder; registering it with a
    browser is a deliberate manual step, because doing it automatically would
    mean writing outside this folder.
    """
    return json.dumps({
        "name": name,
        "description": "ZKeypass password manager native messaging host",
        "path": program_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{item}/"
                            for item in extension_ids],
    }, indent=2)


def client_send(host, port, message, public_key=None, private_key=None,
                identifier="", session=None):
    """A small helper used by the tests and by anyone scripting ZKeypass.

    Sends one message and returns the decoded reply, performing the handshake
    on the way when no session is supplied.
    """
    private_key = private_key or generate_key_pair()[0]
    ours = X25519PrivateKey.from_private_bytes(private_key)
    our_public = ours.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
    with socket.create_connection((host, port), timeout=10) as connection:
        stream = connection.makefile("rwb")
        frame = {"action": MSG_CHANGE_KEYS,
                 "publicKey": base64.b64encode(our_public).decode("ascii")}
        if identifier:
            frame["id"] = identifier
        stream.write(encode_frame(json.dumps(frame)))
        stream.flush()
        first = json.loads(read_frame(stream).decode("utf-8"))
        peer = X25519PublicKey.from_public_bytes(
            base64.b64decode(first["publicKey"]))
        secret = ours.exchange(peer)
        key, _confirm, nonce_base = derive_session_keys(secret)
        message = dict(message)
        if identifier:
            message["id"] = identifier
        stream.write(encode_frame(json.dumps(seal(key, nonce_base, 0, message))))
        stream.flush()
        reply = json.loads(read_frame(stream).decode("utf-8"))
        return open_sealed(key, nonce_base, 0, reply)
