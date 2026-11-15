"""Open a database with Windows Hello: PIN, fingerprint or face.

After the master password has worked once, ZKeypass can keep it for the next
start, sealed so that only Windows Hello on this computer, for this Windows
user, can open it again.  This is the same idea as "use fingerprint next
time" on an Android password manager, and the same method KeePassXC uses.

How the password is protected
-----------------------------
Windows Hello keeps a private key inside the computer's security chip (TPM)
or its own protected store.  The key never leaves it, and it signs only
after the user proves who they are with a PIN, a finger or a face.

1. ZKeypass asks Windows Hello to sign a random challenge, 32 bytes picked for
   this database.
2. The signature is an RSA PKCS#1 signature, which is the same every time
   for the same challenge and the same key.  It is stretched with HKDF into
   an AES-256 key.
3. The master password, and the path of the key file if there is one, are
   sealed with AES-256-GCM under that key and written to
   data\\quick_unlock.json, together with the challenge.

The file alone opens nothing: without the Windows Hello key there is no
signature, so there is no AES key.  Copying the ZKeypass folder to another
computer, or another Windows account, makes the record useless, and ZKeypass
simply asks for the master password there.

Databases that also need a hardware security key are never offered this,
since the point of the security key is that it must be present.

The Windows Runtime calls come from the pywinrt packages bundled in libs.
Without them, or on a computer without Windows Hello, available() says no
and the rest of ZKeypass carries on with passwords as before.
"""

import base64
import json
import os
import threading
import time

from . import paths
from . import lang

CREDENTIAL_NAME = "ZKPass quick unlock"
STORE_FILE = os.path.join(paths.DATA_DIR, "quick_unlock.json")
HKDF_INFO = b"ZKPass Windows Hello quick unlock v1"

_lock = threading.Lock()
_current_operation = None


class HelloError(Exception):
    """Windows Hello could not be used; the message says why, in words."""


class HelloCancelled(HelloError):
    """The person closed the Windows Hello window."""


class HelloKeyMissing(HelloError):
    """The Windows Hello key is gone, so stored records can never open."""


# ------------------------------------------------------------------ storage

def _key(path):
    return os.path.normcase(os.path.abspath(path or ""))


def _load():
    try:
        with open(STORE_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            data.setdefault("databases", {})
            data.setdefault("declined", [])
            return data
    except (OSError, ValueError):
        pass
    return {"version": 1, "databases": {}, "declined": []}


def _save(data):
    os.makedirs(os.path.dirname(STORE_FILE), exist_ok=True)
    tmp = STORE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, STORE_FILE)


def is_set_up(path):
    """True when this database has a Windows Hello record on this computer."""
    return _key(path) in _load()["databases"]


def was_declined(path):
    return _key(path) in _load()["declined"]


def set_declined(path, declined=True):
    with _lock:
        data = _load()
        items = [item for item in data["declined"] if item != _key(path)]
        if declined:
            items.append(_key(path))
        data["declined"] = items
        _save(data)


def forget(path):
    """Remove this database's record.  The password is then asked again."""
    with _lock:
        data = _load()
        data["databases"].pop(_key(path), None)
        _save(data)


def forget_all():
    with _lock:
        data = _load()
        data["databases"] = {}
        _save(data)


def _older_stores():
    """quick_unlock.json of older ZKPass or ZKeypass folders beside this one.

    A new build is usually unpacked next to the old one (for example
    portables\\ZKPass and portables\\ZKeypass).  The old data folder is data
    beside the old program or, in the oldest builds, ZKPass\\data inside it.
    """
    own = os.path.normcase(os.path.abspath(STORE_FILE))
    parent = os.path.dirname(os.path.abspath(paths.ROOT_DIR))
    found = []
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return found
    for name in names:
        if not name.lower().startswith(("zkpass", "zkeypass")):
            continue
        for sub in ("data", os.path.join("ZKPass", "data"),
                    os.path.join("ZKeypass", "data")):
            store = os.path.join(parent, name, sub, "quick_unlock.json")
            if (os.path.normcase(os.path.abspath(store)) != own
                    and os.path.isfile(store)):
                found.append(store)
    return found


def _same_file(first, second):
    import hashlib

    try:
        if os.path.getsize(first) != os.path.getsize(second):
            return False
        digests = []
        for name in (first, second):
            with open(name, "rb") as handle:
                digests.append(hashlib.sha256(handle.read()).digest())
        return digests[0] == digests[1]
    except OSError:
        return False


def adopt_older(path):
    """Take over the Windows Hello record an older build made for this file.

    When a database was copied out of an older ZKPass or ZKeypass folder,
    that folder's record still opens it: the Windows Hello key is the same
    one (CREDENTIAL_NAME has not changed).  A record is taken only for a
    file with the same name and exactly the same content as the database it
    was made for, and it keeps the place it was sealed for, which unlock()
    needs.  Returns True when a record was taken over.
    """
    if is_set_up(path):
        return False
    target = _key(path)
    for store in _older_stores():
        try:
            with open(store, "r", encoding="utf-8") as handle:
                records = json.load(handle).get("databases") or {}
        except (OSError, ValueError, AttributeError):
            continue
        for old_key, record in records.items():
            if (not isinstance(record, dict) or old_key == target
                    or os.path.basename(old_key) != os.path.basename(target)
                    or not _same_file(old_key, path)):
                continue
            taken = dict(record)
            taken.setdefault("sealed_for", old_key)
            with _lock:
                data = _load()
                data["databases"][target] = taken
                _save(data)
            return True
    return False


# ------------------------------------------------------- Windows Runtime

def _winrt():
    """Import the Windows Runtime pieces, or raise HelloError in words."""
    if os.name != "nt":
        raise HelloError(lang.t(
            "errors", "windows_hello_is_only_available_on",
            "Windows Hello is only available on Windows."))
    try:
        import winrt.windows.storage.streams  # noqa: F401  (buffers)
        from winrt.windows.security.credentials import (
            KeyCredentialCreationOption, KeyCredentialManager,
            KeyCredentialStatus)
    except Exception as error:
        raise HelloError(lang.t(
            "errors", "the_windows_hello_support_files_are",
            "The Windows Hello support files are missing from ZKeypass's libs "
            "folder: {error}",
            error=error))
    try:
        import winrt.runtime as runtime

        runtime.init_apartment(runtime.ApartmentType.MULTI_THREADED)
    except Exception:
        pass  # this thread already has an apartment, which is fine
    return KeyCredentialManager, KeyCredentialCreationOption, KeyCredentialStatus


def _wait(operation):
    """Block this worker thread until a Windows Runtime call finishes."""
    global _current_operation
    _current_operation = operation
    try:
        return operation.get()
    except Exception as error:
        if "cancel" in str(error).lower():
            raise HelloCancelled(lang.t(
                "errors", "windows_hello_was_cancelled",
                "Windows Hello was cancelled."))
        raise HelloError(lang.t(
            "errors", "windows_hello_did_not_answer",
            "Windows Hello did not answer: {error}",
            error=error))
    finally:
        _current_operation = None


def cancel_current():
    """Close a Windows Hello window that is still waiting, if there is one."""
    operation = _current_operation
    if operation is not None:
        try:
            operation.cancel()
        except Exception:
            pass


def _bring_prompt_forward():
    """Put the Windows Hello window in front, so the screen reader is in it.

    A desktop program's Hello prompt can open behind the program's own
    window.  KeePassXC works around it the same way: find the prompt by its
    window class and bring it to the front.
    """
    try:
        import ctypes

        user32 = ctypes.windll.user32
    except Exception:
        return
    for _attempt in range(60):
        handle = user32.FindWindowW("Credential Dialog Xaml Host", None)
        if handle:
            user32.SetForegroundWindow(handle)
            return
        time.sleep(0.1)


def _prompt_helper():
    threading.Thread(target=_bring_prompt_forward, daemon=True).start()


def _status_text(status, statuses):
    names = {
        statuses.USER_CANCELED: lang.t(
            "dialogs", "windows_hello_was_cancelled",
            "Windows Hello was cancelled."),
        statuses.USER_PREFERS_PASSWORD: lang.t(
            "dialogs", "you_chose_to_use_the_password",
            "You chose to use the password instead."),
        statuses.SECURITY_DEVICE_LOCKED: lang.t(
            "dialogs", "the_security_chip_is_locked_after",
            "The security chip is locked after too many tries. Wait, then "
            "try again."),
        statuses.NOT_FOUND: lang.t(
            "dialogs", "the_windows_hello_key_for_zkeypass",
            "The Windows Hello key for ZKeypass is missing."),
    }
    return names.get(status, f"Windows Hello failed with status {int(status)}.")


def _raise_for(status, statuses):
    if status == statuses.USER_CANCELED:
        raise HelloCancelled(_status_text(status, statuses))
    if status == statuses.USER_PREFERS_PASSWORD:
        raise HelloCancelled(_status_text(status, statuses))
    if status == statuses.NOT_FOUND:
        raise HelloKeyMissing(_status_text(status, statuses))
    raise HelloError(_status_text(status, statuses))


def available():
    """(True, "") when Windows Hello can be used, else (False, reason).

    Safe to call on the main thread: it asks Windows only whether a PIN,
    finger or face is set up, and shows nothing.
    """
    result = {}

    def check():
        try:
            manager, _options, _statuses = _winrt()
            result["ok"] = bool(_wait(manager.is_supported_async()))
            if not result["ok"]:
                result["why"] = (lang.t(
                    "dialogs", "windows_hello_is_not_set_up",
                    "Windows Hello is not set up for this Windows account. "
                    "Set up a PIN in Windows Settings, Accounts, Sign-in "
                    "options."))
        except HelloError as error:
            result["ok"], result["why"] = False, str(error)
        except Exception as error:
            result["ok"], result["why"] = False, lang.t(
                "dialogs", "windows_hello_failed",
                "Windows Hello failed: {error}",
                error=error)

    worker = threading.Thread(target=check, daemon=True)
    worker.start()
    worker.join(10)
    if worker.is_alive():
        return False, lang.t(
            "dialogs", "windows_hello_did_not_answer_in",
            "Windows Hello did not answer in time.")
    return bool(result.get("ok")), result.get("why", "")


def _to_bytes(buffer):
    try:
        return bytes(buffer)
    except TypeError:
        from winrt.windows.storage.streams import DataReader

        reader = DataReader.from_buffer(buffer)
        data = bytearray(buffer.length)
        reader.read_bytes(data)
        return bytes(data)


def _credential(create):
    """The ZKeypass key in Windows Hello, made on first use when create is set."""
    manager, options, statuses = _winrt()
    if create:
        _prompt_helper()
        made = _wait(manager.request_create_async(
            CREDENTIAL_NAME, options.FAIL_IF_EXISTS))
        if made.status == statuses.SUCCESS:
            return made.credential, statuses
        if made.status != statuses.CREDENTIAL_ALREADY_EXISTS:
            _raise_for(made.status, statuses)
    opened = _wait(manager.open_async(CREDENTIAL_NAME))
    if opened.status != statuses.SUCCESS:
        _raise_for(opened.status, statuses)
    return opened.credential, statuses


def _sign(credential, statuses, challenge):
    _prompt_helper()
    signed = _wait(credential.request_sign_async(bytes(challenge)))
    if signed.status != statuses.SUCCESS:
        _raise_for(signed.status, statuses)
    signature = _to_bytes(signed.result)
    if len(signature) < 128:
        raise HelloError(lang.t(
            "errors", "windows_hello_gave_an_unexpected_answer",
            "Windows Hello gave an unexpected answer."))
    return signature


def _aes_key(signature, challenge):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=challenge,
                info=HKDF_INFO).derive(signature)


# ------------------------------------------------------------ the two jobs

def enroll(path, password, keyfile=None):
    """Seal the password for this database.  Shows the Windows Hello prompt.

    Call from a worker thread (see quick_unlock.run_waiting).  Raises
    HelloError, or HelloCancelled when the person closes the prompt.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    challenge = os.urandom(32)
    credential, statuses = _credential(create=True)
    # The signature of a fixed challenge is the same every time with RSA
    # PKCS#1, which is what makes it usable as a key; KeePassXC relies on it
    # too.  unlock() checks the result with AES-GCM, so a key that ever
    # answered differently is caught there and the record is removed.
    key = _aes_key(_sign(credential, statuses, challenge), challenge)
    nonce = os.urandom(12)
    secret = json.dumps({"password": str(password or ""),
                         "keyfile": keyfile or ""}).encode("utf-8")
    sealed = AESGCM(key).encrypt(nonce, secret, _key(path).encode("utf-8"))
    record = {
        "challenge": base64.b64encode(challenge).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "sealed": base64.b64encode(sealed).decode("ascii"),
        "created": int(time.time()),
    }
    with _lock:
        data = _load()
        data["databases"][_key(path)] = record
        data["declined"] = [item for item in data["declined"]
                            if item != _key(path)]
        _save(data)


def unlock(path):
    """Return (password, keyfile) for this database after Windows Hello.

    Call from a worker thread.  Raises HelloCancelled when the person closes
    the prompt, HelloKeyMissing when the Hello key is gone (the record is then
    removed), and HelloError for anything else.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    record = _load()["databases"].get(_key(path))
    if not record:
        raise HelloError(lang.t(
            "errors", "windows_hello_is_not_set_up",
            "Windows Hello is not set up for this database."))
    try:
        challenge = base64.b64decode(record["challenge"])
        nonce = base64.b64decode(record["nonce"])
        sealed = base64.b64decode(record["sealed"])
    except (KeyError, ValueError):
        forget(path)
        raise HelloError(lang.t(
            "errors", "the_windows_hello_record_for_this",
            "The Windows Hello record for this database was damaged and has "
            "been removed."))
    try:
        credential, statuses = _credential(create=False)
    except HelloKeyMissing:
        forget_all()
        raise HelloKeyMissing(lang.t(
            "errors", "the_windows_hello_key_for_zkeypass",
            "The Windows Hello key for ZKeypass is gone, for example after a "
            "Windows PIN reset. Type the master password, and Windows Hello "
            "can be set up again."))
    key = _aes_key(_sign(credential, statuses, challenge), challenge)
    try:
        # A record taken over from an older folder is opened with the place
        # it was sealed for (adopt_older).
        secret = AESGCM(key).decrypt(
            nonce, sealed,
            (record.get("sealed_for") or _key(path)).encode("utf-8"))
        values = json.loads(secret.decode("utf-8"))
    except Exception:
        forget(path)
        raise HelloError(lang.t(
            "errors", "windows_hello_answered_but_the_saved",
            "Windows Hello answered, but the saved password could not be "
            "opened, so it has been removed. Type the master password once "
            "to set it up again."))
    return values.get("password") or "", values.get("keyfile") or None
