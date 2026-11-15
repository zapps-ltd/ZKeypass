"""Speak a short sentence through the screen reader that is running.

The status bar is where ZKeypass puts the result of every action, but screen
readers do not read a status bar by themselves.  speak() hands the same
sentence to the screen reader directly, so "Password copied" is heard the
moment Control Shift C is pressed, wherever the focus is.

Tried in this order, and the first that works is the only one used, so
nothing is said twice:

    JAWS        its own FreedomSci.JawsApi COM object, SayString
    NVDA        nvdaControllerClient.dll, when a copy sits in libs or
                beside the program; NVDA does not install it itself
    Any other   a Windows UI Automation notification, which Narrator,
                NVDA and JAWS all read

Nothing here ever raises: a sentence that cannot be spoken is still on the
status bar.

Whether to speak at all is the setting "announce_actions":

    auto        the default: only while a screen reader is running, so a
                sighted user without one never hears anything
    always      even without a screen reader detected (UI Automation)
    never       never; the status bar and the banner still show it

A screen reader counts as running when its process is found (JAWS, NVDA,
Narrator, ZoomText or Fusion, Dolphin SuperNova or ScreenReader), or when
Windows' own "a screen reader is
running" flag is set, which most screen readers raise.  The answer is kept
for two seconds, so starting or closing a screen reader is noticed at once.
"""

import ctypes
import os
import sys
import time
from ctypes import wintypes

from . import paths
from . import lang

# Process names, lower case, of the screen readers ZKeypass knows by name.
SCREEN_READERS = {
    "jfw.exe": "JAWS",
    "nvda.exe": "NVDA",
    "narrator.exe": "Narrator",
    "zt.exe": "ZoomText",
    "fusion.exe": "Fusion",
    "snova.exe": "Dolphin SuperNova",
    "hal.exe": "Dolphin ScreenReader",
}

_mode = "auto"
_detected = {"time": 0.0, "names": ()}

# UI Automation notification values, from UIAutomationCore.h.
_NOTIFICATION_ACTION_COMPLETED = 2
_PROCESSING_IMPORTANT_MOST_RECENT = 1
_PROCESSING_MOST_RECENT = 3

_jaws = None
_nvda = None
_nvda_searched = False


def _window_exists(class_name, title=None):
    try:
        return bool(ctypes.windll.user32.FindWindowW(class_name, title))
    except Exception:
        return False


def _jaws_running():
    return _window_exists("JFWUI2")


def _nvda_running():
    return _window_exists("wxWindowClassNR", "NVDA")


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


def _process_names():
    """Lower-case names of every running process."""
    names = set()
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
        if not snapshot or snapshot == wintypes.HANDLE(-1).value:
            return names
        try:
            entry = _ProcessEntry()
            entry.dwSize = ctypes.sizeof(_ProcessEntry)
            more = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while more:
                names.add(entry.szExeFile.lower())
                more = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
    except Exception:
        pass
    return names


def _windows_flag():
    """Windows' SPI_GETSCREENREADER: set by most screen readers."""
    try:
        value = wintypes.BOOL(False)
        if ctypes.windll.user32.SystemParametersInfoW(0x0046, 0,
                                                      ctypes.byref(value), 0):
            return bool(value.value)
    except Exception:
        pass
    return False


def running_screen_readers(fresh=False):
    """Names of the screen readers running now, such as ("JAWS",).

    "a screen reader" stands for one Windows reports without a name ZKeypass
    knows.  Empty when none is running.
    """
    now = time.monotonic()
    if not fresh and now - _detected["time"] < 2.0:
        return _detected["names"]
    running = _process_names() if sys.platform == "win32" else set()
    found = [name for process, name in SCREEN_READERS.items() if process in running]
    if not found and _windows_flag():
        found = [lang.t("dialogs", "a_screen_reader", "a screen reader")]
    _detected["time"] = now
    _detected["names"] = tuple(dict.fromkeys(found))
    return _detected["names"]


def describe_detection():
    """A sentence for Settings: what is running now."""
    names = running_screen_readers(fresh=True)
    if not names:
        return lang.t(
            "dialogs", "no_screen_reader_is_running_now",
            "No screen reader is running now.")
    return lang.t("dialogs", "running_now", "Running now: ") + ", ".join(names) + "."


def set_mode(mode):
    """"auto", "always" or "never"; see the module notes."""
    global _mode
    _mode = mode if mode in ("auto", "always", "never") else "auto"


def enabled():
    """Whether announcements are spoken at the moment."""
    if _mode == "never":
        return False
    if _mode == "always":
        return True
    return bool(running_screen_readers())


def _speak_jaws(text, interrupt):
    global _jaws
    for attempt in (1, 2):
        if _jaws is None:
            try:
                # Dynamic dispatch writes no generated code to disk.
                from win32com.client import dynamic

                _jaws = dynamic.Dispatch("FreedomSci.JawsApi")
            except Exception:
                try:
                    import comtypes.client

                    _jaws = comtypes.client.CreateObject("FreedomSci.JawsApi")
                except Exception:
                    return False
        try:
            _jaws.SayString(text, bool(interrupt))
            return True
        except Exception:
            # JAWS was restarted since the object was made; make a new one.
            _jaws = None
    return False


def _load_nvda():
    global _nvda, _nvda_searched
    if _nvda_searched:
        return _nvda
    _nvda_searched = True
    names = ("nvdaControllerClient64.dll", "nvdaControllerClient.dll")
    folders = [paths.LIBS_DIR, paths.APP_DIR, os.path.join(paths.LIBS_DIR, "x64")]
    for folder in folders:
        for name in names:
            candidate = os.path.join(folder, name)
            if not os.path.isfile(candidate):
                continue
            try:
                library = ctypes.WinDLL(candidate)
                library.nvdaController_speakText.argtypes = [ctypes.c_wchar_p]
                _nvda = library
                return _nvda
            except Exception:
                continue
    return None


def _speak_nvda(text, interrupt):
    library = _load_nvda()
    if library is None:
        return False
    try:
        if library.nvdaController_testIfRunning() != 0:
            return False
        if interrupt:
            library.nvdaController_cancelSpeech()
        return library.nvdaController_speakText(text) == 0
    except Exception:
        return False


def _speak_uia(text, interrupt, hwnd):
    """Raise a UI Automation notification on our own window."""
    if not hwnd:
        return False
    try:
        uia = ctypes.WinDLL("UIAutomationCore")
        raise_event = uia.UiaRaiseNotificationEvent  # Windows 10 1709 and later
    except (OSError, AttributeError):
        return False
    try:
        if not uia.UiaClientsAreListening():
            return False
        provider = ctypes.c_void_p()
        uia.UiaHostProviderFromHwnd.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_void_p)]
        if uia.UiaHostProviderFromHwnd(hwnd, ctypes.byref(provider)) != 0 \
                or not provider:
            return False
        oleaut = ctypes.WinDLL("oleaut32")
        oleaut.SysAllocString.restype = ctypes.c_void_p
        oleaut.SysAllocString.argtypes = [ctypes.c_wchar_p]
        oleaut.SysFreeString.argtypes = [ctypes.c_void_p]
        display = oleaut.SysAllocString(text)
        activity = oleaut.SysAllocString("ZKeypass")
        try:
            raise_event.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_void_p, ctypes.c_void_p]
            result = raise_event(
                provider, _NOTIFICATION_ACTION_COMPLETED,
                _PROCESSING_IMPORTANT_MOST_RECENT if interrupt
                else _PROCESSING_MOST_RECENT, display, activity)
        finally:
            oleaut.SysFreeString(display)
            oleaut.SysFreeString(activity)
            # IUnknown::Release is the third entry of the interface table.
            table = ctypes.cast(provider, ctypes.POINTER(
                ctypes.POINTER(ctypes.c_void_p))).contents
            ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(table[2])(provider)
        return result == 0
    except Exception:
        return False


def speak(text, interrupt=True, window=None):
    """Say text through the running screen reader.  True when it was handed on.

    window is any wx window of ours; the UI Automation route needs its handle.
    """
    text = (text or "").strip()
    if not text or sys.platform != "win32" or not enabled():
        return False
    if _jaws_running() and _speak_jaws(text, interrupt):
        return True
    if _nvda_running() and _speak_nvda(text, interrupt):
        return True
    hwnd = 0
    if window is not None:
        try:
            hwnd = window.GetHandle()
        except Exception:
            hwnd = 0
    return _speak_uia(text, interrupt, hwnd)
