"""Hardware challenge-response: HMAC-SHA1 on a YubiKey.

KeePassXC, KeePass 2 and ZKeypass all use the same scheme: a challenge is sent
to the token, the token answers with HMAC-SHA1, and the answer joins the
password and the key file in the composite master key.  Nothing about the
challenge or the answer is written to the database, so a stolen database file
cannot be opened without the physical key.

The token is reached over its HID interface with the YubiKey personalisation
protocol, implemented here with ctypes so that no extra package is needed:

  * HidD_GetHidGuid and the SetupAPI device interface calls find the device
  * HidD_SetFeature and HidD_GetFeature carry 64 byte reports
  * each report has an eight byte header: report number, sequence number,
    three reserved bytes, then the big endian payload length
  * the payload for this feature is 0x20, the slot byte, then 64 challenge
    bytes; the answer repeats the feature and slot then gives 20 HMAC bytes

If no token is present every function here fails with a readable message and
the program carries on using the password alone.
"""

import ctypes
import os
import struct
from ctypes import wintypes
from . import lang

# Feature and slot constants from the YubiKey OTP HID protocol.
FEATURE_CHALLENGE_RESPONSE = 0x20
SLOT_HMAC1 = 0x30
SLOT_HMAC2 = 0x38

VENDOR_YUBICO = 0x1050

# Product identifiers that carry the OTP HID interface with challenge-response.
PRODUCT_IDS = {
    0x0010: "YubiKey (original)",
    0x0110: "YubiKey 2",
    0x0111: "YubiKey 2",
    0x0112: "YubiKey 2",
    0x0113: "YubiKey 2",
    0x0114: "YubiKey NEO",
    0x0115: "YubiKey NEO",
    0x0116: "YubiKey 3",
    0x0401: "YubiKey 4",
    0x0402: "YubiKey 4",
    0x0403: "YubiKey 4",
    0x0404: "YubiKey 4",
    0x0405: "YubiKey 4",
    0x0406: "YubiKey NEO",
    0x0407: "YubiKey 4",
    0x0408: "YubiKey 4",
    0x0409: "YubiKey 4",
    0x040A: "YubiKey 4",
    0x040B: "YubiKey 4",
    0x040C: "YubiKey 4",
    0x040D: "YubiKey 4",
    0x040E: "YubiKey 4",
    0x040F: "YubiKey 4",
    0x0410: "YubiKey 5",
    0x0402 + 0x100: "YubiKey 5",
}

REPORT_SIZE = 64
HEADER_SIZE = 8
CHALLENGE_LENGTH = 64
RESPONSE_LENGTH = 20
MAX_PAYLOAD = REPORT_SIZE + 6

GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
DIGCF_PRESENT = 0x02
DIGCF_DEVICEINTERFACE = 0x10

GUID = getattr(wintypes, "GUID", None)
if GUID is None:  # pragma: no cover - GUID exists on Windows
    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_byte * 8)]


class YubiKeyError(Exception):
    """Raised with a message meant to be shown to the user."""


class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD),
                ("InterfaceClassGuid", GUID),
                ("Flags", wintypes.DWORD),
                ("Reserved", ctypes.POINTER(ctypes.c_ulong))]


class HIDD_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Size", wintypes.ULONG), ("VendorID", wintypes.USHORT),
                ("ProductID", wintypes.USHORT), ("VersionNumber", wintypes.USHORT)]


def _hid():
    return ctypes.WinDLL("hid", use_last_error=True)


def _setupapi():
    return ctypes.WinDLL("setupapi", use_last_error=True)


def _kernel32():
    return ctypes.WinDLL("kernel32", use_last_error=True)


def available():
    """True when a HID token could be reached on this system at all."""
    try:
        _hid()
        _setupapi()
        return True
    except OSError:
        return False


def _device_paths():
    """Every present HID device interface path, as plain strings."""
    hid = _hid()
    setupapi = _setupapi()
    guid = GUID()
    hid.HidD_GetHidGuid(ctypes.byref(guid))
    devices = setupapi.SetupDiGetClassDevsW(
        ctypes.byref(guid), None, None,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)
    if devices == INVALID_HANDLE_VALUE:
        raise YubiKeyError(lang.t(
            "errors", "windows_would_not_list_the_connected",
            "Windows would not list the connected USB devices."))
    paths = []
    try:
        index = 0
        while True:
            interface = SP_DEVICE_INTERFACE_DATA()
            interface.cbSize = ctypes.sizeof(interface)
            if not setupapi.SetupDiEnumDeviceInterfaces(
                    devices, None, ctypes.byref(guid), index,
                    ctypes.byref(interface)):
                break
            index += 1
            needed = wintypes.DWORD(0)
            setupapi.SetupDiGetDeviceInterfaceDetailW(
                devices, ctypes.byref(interface), None, 0,
                ctypes.byref(needed), None)
            if not needed.value:
                continue
            buffer = ctypes.create_string_buffer(needed.value)
            ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD))[0] = \
                ctypes.sizeof(wintypes.DWORD) + ctypes.sizeof(ctypes.c_wchar)
            if setupapi.SetupDiGetDeviceInterfaceDetailW(
                    devices, ctypes.byref(interface), buffer, needed.value,
                    ctypes.byref(needed), None):
                paths.append(ctypes.wstring_at(ctypes.addressof(buffer) +
                                               ctypes.sizeof(wintypes.DWORD)))
    finally:
        setupapi.SetupDiDestroyDeviceInfoList(devices)
    return paths


def _open(path, access):
    kernel32 = _kernel32()
    handle = kernel32.CreateFileW(path, access,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                                  OPEN_EXISTING, 0, None)
    if handle == INVALID_HANDLE_VALUE:
        raise YubiKeyError(lang.t(
            "errors", "the_security_key_could_not_be_2",
            "The security key could not be opened. Close any other program "
            "that is using it and try again."))
    return handle


def _close(handle):
    try:
        _kernel32().CloseHandle(handle)
    except OSError:
        pass


def list_keys():
    """Return [{"path", "vendor_id", "product_id", "name"}] for Yubico keys."""
    if not available():
        return []
    hid = _hid()
    found = []
    for path in _device_paths():
        try:
            handle = _open(path, 0)
        except YubiKeyError:
            continue
        try:
            attributes = HIDD_ATTRIBUTES()
            attributes.Size = ctypes.sizeof(attributes)
            if not hid.HidD_GetAttributes(handle, ctypes.byref(attributes)):
                continue
            if attributes.VendorID != VENDOR_YUBICO:
                continue
            found.append({
                "path": path,
                "vendor_id": attributes.VendorID,
                "product_id": attributes.ProductID,
                "name": PRODUCT_IDS.get(attributes.ProductID,
                                        "Yubico security key"),
            })
        finally:
            _close(handle)
    return found


def present():
    """True when at least one Yubico key is plugged in."""
    try:
        return bool(list_keys())
    except (YubiKeyError, OSError):
        return False


class HidTransport:
    """The byte level transport: feature reports in and out."""

    def __init__(self, path=None, handle=None):
        self._close_handle = handle is None
        if handle is not None:
            self.handle = handle
        else:
            if path is None:
                keys = list_keys()
                if not keys:
                    raise YubiKeyError(lang.t(
                        "errors", "no_security_key_was_found_plug",
                        "No security key was found. Plug the key in and try "
                        "again."))
                path = keys[0]["path"]
            self.path = path
            self.handle = _open(path, GENERIC_READ | GENERIC_WRITE)
        self.sequence = 0

    def close(self):
        if self._close_handle and getattr(self, "handle", None):
            _close(self.handle)
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_exception):
        self.close()

    def write_frame(self, payload):
        """Send one frame: eight byte header, payload, zero padding."""
        if len(payload) > REPORT_SIZE:
            raise YubiKeyError(lang.t(
                "errors", "the_message_for_the_security_key",
                "The message for the security key is too long."))
        self.sequence = (self.sequence + 1) & 0x7F
        frame = bytearray(REPORT_SIZE + 1)
        frame[0] = 0x00                       # HID report number
        frame[1] = self.sequence
        frame[6] = (len(payload) >> 8) & 0xFF
        frame[7] = len(payload) & 0xFF
        frame[HEADER_SIZE:HEADER_SIZE + len(payload)] = payload
        hid = _hid()
        if not hid.HidD_SetFeature(self.handle, bytes(frame), len(frame)):
            raise YubiKeyError(lang.t(
                "errors", "the_security_key_did_not_accept",
                "The security key did not accept the request."))

    def read_frame(self):
        """Read one frame and return its payload."""
        hid = _hid()
        frame = ctypes.create_string_buffer(REPORT_SIZE + 1)
        if not hid.HidD_GetFeature(self.handle, frame, REPORT_SIZE + 1):
            raise YubiKeyError(lang.t(
                "errors", "no_answer_came_back_from_the",
                "No answer came back from the security key."))
        data = frame.raw
        length = (data[6] << 8) | data[7]
        if length <= 0 or length > MAX_PAYLOAD:
            raise YubiKeyError(lang.t(
                "errors", "the_security_key_sent_a_malformed",
                "The security key sent a malformed answer."))
        return data[HEADER_SIZE:HEADER_SIZE + length]

    def command(self, payload):
        """Write a command and read its answer."""
        self.write_frame(payload)
        return self.read_frame()


def format_challenge(challenge, slot=1):
    """Build the challenge-response command payload."""
    if isinstance(challenge, str):
        challenge = challenge.encode("utf-8")
    if slot not in (1, 2):
        raise YubiKeyError(lang.t(
            "errors", "the_security_key_slot_must_be",
            "The security key slot must be 1 or 2."))
    if len(challenge) > CHALLENGE_LENGTH:
        raise YubiKeyError(lang.t(
            "errors", "a_challenge_may_be_at_most",
            "A challenge may be at most {challenge_length} bytes long.",
            challenge_length=CHALLENGE_LENGTH))
    challenge = challenge.ljust(CHALLENGE_LENGTH, b"\x00")
    return bytes([FEATURE_CHALLENGE_RESPONSE,
                  SLOT_HMAC1 if slot == 1 else SLOT_HMAC2]) + challenge


def parse_response(answer, slot=1):
    """Check an answer frame and return the 20 byte HMAC.

    Older keys echo the slot as a small number and newer ones as 0x30 or
    0x38, so only the feature byte and the length are insisted on; the last
    twenty bytes are the HMAC-SHA1 answer either way.
    """
    if not answer:
        raise YubiKeyError(lang.t(
            "errors", "the_security_key_sent_an_empty",
            "The security key sent an empty answer."))
    if answer[0] != FEATURE_CHALLENGE_RESPONSE:
        raise YubiKeyError(lang.t(
            "errors", "the_security_key_does_not_support",
            "The security key does not support challenge-response on that "
            "slot."))
    if len(answer) < 2 + RESPONSE_LENGTH:
        raise YubiKeyError(lang.t(
            "errors", "the_answer_from_the_security_key",
            "The answer from the security key was too short. Check that the "
            "slot is set to challenge-response."))
    if len(answer) >= 2 and answer[1] in (1, 2, SLOT_HMAC1, SLOT_HMAC2):
        wanted = SLOT_HMAC1 if slot == 1 else SLOT_HMAC2
        if answer[1] == (SLOT_HMAC2 if slot == 1 else SLOT_HMAC1):
            raise YubiKeyError(lang.t(
                "errors", "the_security_key_answered_for_the",
                "The security key answered for the other slot."))
    return answer[-RESPONSE_LENGTH:]


def challenge_response(challenge, slot=1, path=None, transport=None):
    """Send a challenge and return the 20 byte HMAC-SHA1 answer.

    A transport may be supplied for testing; otherwise the first Yubico key
    found on the system is used.
    """
    payload = format_challenge(challenge, slot)
    if transport is not None:
        return parse_response(transport.command(payload), slot)
    with HidTransport(path) as device:
        return parse_response(device.command(payload), slot)


def has_slot_configured(slot=1):
    """True when a key is present and answers a probe challenge."""
    try:
        challenge_response(os.urandom(64), slot)
        return True
    except (YubiKeyError, OSError):
        return False


def describe_keys():
    """One line per key found, for the interface."""
    lines = []
    for index, key in enumerate(list_keys(), start=1):
        lines.append(lang.t(
            "dialogs", "security_key_vendor_0x_product_0x",
            "Security key {index}: {name}, vendor 0x{vendor_id:04X}, product "
            "0x{product_id:04X}",
            index=index,
            name=key['name'],
            vendor_id=key['vendor_id'],
            product_id=key['product_id']))
    return lines


class SoftToken:
    """A test double standing in for a real key.

    It answers with HMAC-SHA1 over the challenge using its own secret, which
    is exactly what the hardware does, so the surrounding code can be tested
    without a key plugged in.
    """

    def __init__(self, secret=b"test-secret", slot=1, serial=1):
        self.secret = secret
        self.slot = slot
        self.serial = serial
        self.commands = []

    def command(self, payload):
        import hashlib
        import hmac as hmaclib

        self.commands.append(payload)
        if payload[0] != FEATURE_CHALLENGE_RESPONSE:
            raise YubiKeyError(lang.t(
                "errors", "the_test_token_only_supports_challenge",
                "The test token only supports challenge-response."))
        if payload[1] != (SLOT_HMAC1 if self.slot == 1 else SLOT_HMAC2):
            # A real key answers a wrong slot with a loud error frame.
            return bytes([FEATURE_CHALLENGE_RESPONSE, payload[1]])

        digest = hmaclib.new(self.secret, payload[2:], hashlib.sha1).digest()
        return bytes([FEATURE_CHALLENGE_RESPONSE, payload[1]]) + digest
