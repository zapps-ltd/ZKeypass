"""Start ZKeypass when you sign in to Windows, locked or unlocked.

Starting with Windows is the one thing ZKeypass writes outside its own folder:
a value named ZKeypass under the current user's
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, only while
"Start ZKeypass when I sign in to Windows" is ticked.  ZKeypass then starts in
the notification area with --startup.

What it starts as:

    Locked      the default.  The tray icon is amber; Show ZKeypass asks for
                Windows Hello or the master password as usual.
    Unlocked    only with "Open the current database at sign-in without
                asking" ticked, and only while your Windows account is
                protected by a password, which Windows Hello sign-in also
                needs.  The master password is then sealed with Windows' own
                data protection (DPAPI) for your Windows account, in
                data\\startup_unlock.json: it opens only for you, signed in on
                this computer.  When Windows sign-in has no password, anyone
                at the computer would be "you", so ZKeypass refuses and starts
                locked instead.

A portable copy moved elsewhere rewrites the Run value on its next start, and
turning the option off removes it.
"""

import base64
import ctypes
import json
import os
import sys
from ctypes import wintypes

from . import paths
from . import lang

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "ZKeypass"
STARTUP_ARGUMENT = "--startup"
SEAL_FILE = os.path.join(paths.DATA_DIR, "startup_unlock.json")
_ENTROPY = b"ZKPass startup unlock v1"


# ------------------------------------------------------------ Run registry

def command():
    """The command line Windows runs at sign-in for this copy of ZKeypass."""
    if paths.FROZEN:
        return f'"{os.path.abspath(sys.executable)}" {STARTUP_ARGUMENT}'
    folder = os.path.dirname(os.path.abspath(sys.executable))
    windowless = os.path.join(folder, "pythonw.exe")
    interpreter = windowless if os.path.isfile(windowless) else sys.executable
    script = os.path.join(paths.ROOT_DIR, "zkeypass.py")
    return f'"{interpreter}" "{script}" {STARTUP_ARGUMENT}'


def registered_command():
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            return winreg.QueryValueEx(key, RUN_VALUE)[0]
    except OSError:
        return None


def is_registered():
    """True when Windows starts this copy of ZKeypass at sign-in."""
    current = registered_command()
    return bool(current) and os.path.normcase(current) == os.path.normcase(command())


def register():
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                        winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, command())


def unregister():
    """Remove the Run value, but only when it starts this copy."""
    if not is_registered():
        return
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except OSError:
        pass


def sync(settings):
    """Make the Run value match the setting.  Returns an error text or ""."""
    try:
        if settings.get("run_at_startup"):
            if not is_registered():
                register()
        else:
            unregister()
    except OSError as error:
        return lang.t(
            "dialogs", "windows_did_not_accept_the_start",
            "Windows did not accept the start-up setting: {error}",
            error=error)
    return ""


# ------------------------------------------------- Windows sign-in check

def windows_signin_protected():
    """Whether this Windows account needs a password to sign in.

    Asks Windows to check an empty password for this account.  An account
    with a password refuses it; one without either accepts it or refuses it
    only because blank passwords are limited to the console.  Windows Hello
    PIN and fingerprint sign-in always sit on top of an account password.
    """
    if sys.platform != "win32":
        return False
    try:
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        size = wintypes.DWORD(257)
        name = ctypes.create_unicode_buffer(257)
        if not advapi.GetUserNameW(name, ctypes.byref(size)):
            return False
        token = wintypes.HANDLE()
        advapi.LogonUserW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                      wintypes.LPCWSTR, wintypes.DWORD,
                                      wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        # LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT
        if advapi.LogonUserW(name.value, ".", "", 3, 0, ctypes.byref(token)):
            ctypes.windll.kernel32.CloseHandle(token)
            return False
        error = ctypes.get_last_error()
    except Exception:
        return False
    # Only 1326, wrong user name or password, means there is a password.
    # 1327 (blank passwords limited to the console), 1385 (logon type not
    # granted) and the expiry errors all come after the empty password was
    # accepted; anything else is unknown, and unknown counts as unprotected.
    return error == 1326


# ---------------------------------------------------------- DPAPI sealing

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data):
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _dpapi(data, entropy, protect):
    crypt = ctypes.WinDLL("crypt32")
    source, _keep = _blob(data)
    extra, _keep_extra = _blob(entropy)
    result = _Blob()
    # CRYPTPROTECT_UI_FORBIDDEN: never show a prompt.
    if protect:
        ok = crypt.CryptProtectData(ctypes.byref(source), "ZKeypass", ctypes.byref(extra),
                                    None, None, 0x1, ctypes.byref(result))
    else:
        ok = crypt.CryptUnprotectData(ctypes.byref(source), None, ctypes.byref(extra),
                                      None, None, 0x1, ctypes.byref(result))
    if not ok:
        raise OSError(ctypes.GetLastError(), lang.t(
            "errors", "windows_data_protection_failed",
            "Windows data protection failed"))
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(result.pbData)


def _entropy(path):
    return _ENTROPY + os.path.normcase(os.path.abspath(path)).encode("utf-8")


def seal(path, password, keyfile=None):
    """Seal the master password of one database for this Windows account."""
    payload = json.dumps({"password": str(password),
                          "keyfile": keyfile or ""}).encode("utf-8")
    sealed = _dpapi(payload, _entropy(path), protect=True)
    record = {"version": 1, "path": os.path.abspath(path),
              "sealed": base64.b64encode(sealed).decode("ascii")}
    os.makedirs(paths.DATA_DIR, exist_ok=True)
    with open(SEAL_FILE, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2)


def sealed_path():
    try:
        with open(SEAL_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle).get("path") or ""
    except (OSError, ValueError):
        return ""


def unseal():
    """(path, password, keyfile) from the sealed record, or None."""
    try:
        with open(SEAL_FILE, "r", encoding="utf-8") as handle:
            record = json.load(handle)
        path = record["path"]
        payload = json.loads(_dpapi(base64.b64decode(record["sealed"]),
                                    _entropy(path), protect=False))
        return path, payload["password"], payload.get("keyfile") or None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def forget():
    """Delete the sealed record.  Its contents are overwritten first."""
    try:
        size = os.path.getsize(SEAL_FILE)
        with open(SEAL_FILE, "r+b") as handle:
            handle.write(b"\0" * size)
        os.remove(SEAL_FILE)
    except OSError:
        pass


def open_sealed():
    """Open the sealed database at sign-in.

    Returns (vault, PasswordPair, "") on success, or (None, None, reason).
    The record is forgotten when it no longer opens the database.
    """
    if not windows_signin_protected():
        return None, None, (lang.t(
            "dialogs", "windows_sign_in_has_no_password",
            "Windows sign-in has no password, so ZKeypass started locked."))
    found = unseal()
    if not found:
        return None, None, lang.t(
            "dialogs", "there_is_no_sealed_database_to",
            "There is no sealed database to open.")
    path, password, keyfile = found
    if not os.path.isfile(path):
        return None, None, lang.t(
            "dialogs", "is_no_longer_there",
            "{path} is no longer there.",
            path=path)
    from .kdbx_vault import open_any
    from .vault import PasswordPair

    try:
        vault = open_any(path, password, keyfile, None)
    except Exception:
        forget()
        return None, None, (lang.t(
            "dialogs", "the_sealed_master_password_no_longer",
            "The sealed master password no longer opens the database, so "
            "ZKeypass started locked."))
    return vault, PasswordPair(password, keyfile), ""
