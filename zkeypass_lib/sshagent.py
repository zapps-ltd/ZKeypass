"""Built-in SSH agent for private keys held inside the vault.

The agent speaks the standard ssh-agent protocol over a Windows named pipe,
so Git for Windows and OpenSSH can use it through SSH_AUTH_SOCK alternative
commands.  Only the request types that matter for unlocking keys are handled:
list identities and sign with a loaded key.

Keys are held in memory only, inside the vault process.  Nothing is written
to a key file on disk and nothing leaves the program folder.
"""

import base64
import ctypes
import hashlib
import struct
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from . import lang

# ssh-agent protocol message numbers
SSH_AGENT_FAILURE = 5
SSH_AGENT_SUCCESS = 6
SSH_AGENT_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENT_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

DEFAULT_PIPE = r"\\.\pipe\zkeypass-agent"


def pack_string(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return struct.pack(">I", len(data)) + data


def pack_mpint(number):
    if number == 0:
        return pack_string(b"")
    length = (number.bit_length() + 8) // 8
    return pack_string(number.to_bytes(length, "big", signed=False))


def read_string(buffer, offset):
    length = struct.unpack(">I", buffer[offset:offset + 4])[0]
    start = offset + 4
    return buffer[start:start + length], start + length


class LoadedKey:
    def __init__(self, key_id, name, private_key):
        self.key_id = key_id
        self.name = name
        self.private_key = private_key
        self.blob, self.algorithm = public_blob(private_key)
        self.fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(self.blob).digest()).decode().rstrip("=")

    def sign(self, data, algorithm):
        key = self.private_key
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return algorithm, key.sign(data)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
            from cryptography.hazmat.primitives.asymmetric.utils import (
                decode_dss_signature,
            )
            r_value, s_value = decode_dss_signature(signature)
            body = pack_mpint(r_value) + pack_mpint(s_value)
            return algorithm, body
        if isinstance(key, rsa.RSAPrivateKey):
            hash_algorithm = {
                "rsa-sha2-512": hashes.SHA512(),
                "rsa-sha2-256": hashes.SHA256(),
            }.get(algorithm, hashes.SHA1())
            return algorithm, key.sign(data, padding.PKCS1v15(), hash_algorithm)
        raise ValueError(lang.t(
            "errors", "unsupported_key_type",
            "Unsupported key type."))


def public_blob(private_key):
    """Serialise the public half in OpenSSH wire format."""
    public = private_key.public_key()
    if isinstance(public, ed25519.Ed25519PublicKey):
        raw = public.public_bytes(serialization.Encoding.Raw,
                                  serialization.PublicFormat.Raw)
        return pack_string("ssh-ed25519") + pack_string(raw), "ssh-ed25519"
    if isinstance(public, ec.EllipticCurvePublicKey):
        numbers = public.public_numbers()
        size = (public.curve.key_size + 7) // 8
        point = b"\x04" + numbers.x.to_bytes(size, "big") + \
            numbers.y.to_bytes(size, "big")
        name = "ecdsa-sha2-nistp256"
        return (pack_string(name) + pack_string("nistp256") +
                pack_string(point)), name
    if isinstance(public, rsa.RSAPublicKey):
        numbers = public.public_numbers()
        return (pack_string("ssh-rsa") + pack_mpint(numbers.e) +
                pack_mpint(numbers.n)), "ssh-rsa"
    raise ValueError(lang.t(
        "errors", "unsupported_key_type",
        "Unsupported key type."))


def load_private_key(data, passphrase=None):
    """Accept OpenSSH or PEM private keys, encrypted or not."""
    encoded = passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase
    try:
        return serialization.load_ssh_private_key(data, password=encoded)
    except Exception:
        return serialization.load_pem_private_key(data, password=encoded)


class SshAgentServer:
    """Named-pipe ssh-agent. Started on request, stopped when the vault closes."""

    def __init__(self, pipe_name=DEFAULT_PIPE):
        self.pipe_name = pipe_name
        self._keys = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._handle = None
        self.last_error = ""

    # ------------------------------------------------------------ key storage

    @property
    def running(self):
        return self._running

    def has_key(self, key_id):
        return key_id in self._keys

    def loaded_keys(self):
        return {key_id: {"name": key.name, "fingerprint": key.fingerprint}
                for key_id, key in self._keys.items()}

    def load_key(self, key_id, name, data, passphrase=None):
        private_key = load_private_key(data, passphrase)
        loaded = LoadedKey(key_id, name, private_key)
        with self._lock:
            self._keys[key_id] = loaded
        return {"fingerprint": loaded.fingerprint, "algorithm": loaded.algorithm}

    def unload_key(self, key_id):
        with self._lock:
            self._keys.pop(key_id, None)

    def unload_all(self):
        with self._lock:
            self._keys.clear()

    # ------------------------------------------------------------- protocol

    def handle_message(self, message):
        """Answer one agent request. Returns bytes, or b'' for no reply."""
        if not message:
            return b""
        message_type = message[0]
        body = message[1:]
        if message_type == SSH_AGENT_REQUEST_IDENTITIES:
            with self._lock:
                keys = list(self._keys.values())
            payload = struct.pack(">I", len(keys))
            for key in keys:
                payload += pack_string(key.blob) + pack_string(key.name)
            return bytes([SSH_AGENT_IDENTITIES_ANSWER]) + payload

        if message_type == SSH_AGENT_SIGN_REQUEST:
            blob, offset = read_string(body, 0)
            data, offset = read_string(body, offset)
            flags = struct.unpack(">I", body[offset:offset + 4])[0]
            algorithm = "ssh-rsa" if flags & 4 else "rsa-sha2-256"
            with self._lock:
                key = next((item for item in self._keys.values()
                            if item.blob == blob), None)
            if key is None:
                return bytes([SSH_AGENT_FAILURE])
            try:
                used_algorithm, signature = key.sign(data, algorithm)
            except Exception:
                return bytes([SSH_AGENT_FAILURE])
            payload = pack_string(used_algorithm) + pack_string(signature)
            return bytes([SSH_AGENT_SIGN_RESPONSE]) + payload

        return bytes([SSH_AGENT_FAILURE])

    # ------------------------------------------------------------ pipe server

    def start(self):
        if self._running:
            return
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        for _ in range(50):
            if self._running or self.last_error:
                break
            threading.Event().wait(0.02)
        if self.last_error:
            raise OSError(self.last_error)

    def stop(self):
        self._running = False
        self.unload_all()
        try:
            import ctypes.wintypes as wintypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                self.pipe_name, 0x40000000, 0, None, 3, 0, None)
            if handle != -1:
                kernel32.CloseHandle(handle)
        except Exception:
            pass

    def _serve(self):
        """Accept a connection at a time, then go back to waiting.

        A named pipe instance is created per connection, which keeps the
        threading simple and matches how ssh-agent behaves in practice.
        """
        try:
            kernel32 = ctypes.windll.kernel32
        except AttributeError:
            self.last_error = lang.t(
                "dialogs", "the_ssh_agent_needs_windows_named",
                "The SSH agent needs Windows named pipes.")
            return
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_BYTE = 0x00000000
        PIPE_UNLIMITED_INSTANCES = 255
        INVALID_HANDLE_VALUE = -1

        self._running = True
        while self._running:
            handle = kernel32.CreateNamedPipeW(
                self.pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE,
                PIPE_UNLIMITED_INSTANCES, 8192, 8192, 0, None)
            if handle == INVALID_HANDLE_VALUE:
                self.last_error = (lang.t(
                    "dialogs", "could_not_create_the_named_pipe",
                    "Could not create the named pipe. It may already be in "
                    "use."))
                self._running = False
                return
            self._handle = handle
            if not kernel32.ConnectNamedPipe(handle, None):
                error = kernel32.GetLastError()
                if error != 535:  # ERROR_PIPE_CONNECTED
                    kernel32.CloseHandle(handle)
                    continue
            try:
                self._pump(handle, kernel32)
            finally:
                kernel32.DisconnectNamedPipe(handle)
                kernel32.CloseHandle(handle)
                self._handle = None

    def _pump(self, handle, kernel32):
        buffer = ctypes.create_string_buffer(16384)
        while self._running:
            read = ctypes.c_ulong(0)
            header = ctypes.create_string_buffer(4)
            if not kernel32.ReadFile(handle, header, 4, ctypes.byref(read), None):
                return
            length = struct.unpack(">I", header.raw[:4])[0]
            if length <= 0 or length > 1024 * 1024:
                return
            message = b""
            while len(message) < length:
                chunk = ctypes.create_string_buffer(min(16384, length - len(message)))
                read = ctypes.c_ulong(0)
                if not kernel32.ReadFile(handle, chunk, len(chunk),
                                         ctypes.byref(read), None):
                    return
                message += chunk.raw[:read.value]
            reply = self.handle_message(message)
            if not reply:
                continue
            written = ctypes.c_ulong(0)
            payload = struct.pack(">I", len(reply)) + reply
            out = ctypes.create_string_buffer(payload)
            kernel32.WriteFile(handle, out, len(payload), ctypes.byref(written), None)


def describe_fingerprint(key_id, name, data):
    """Used by the import helper to label keys without loading them."""
    try:
        loaded = LoadedKey(key_id, name, load_private_key(data))
        return loaded.fingerprint
    except Exception as error:
        return lang.t(
            "dialogs", "not_readable",
            "not readable: {error}",
            error=error)
