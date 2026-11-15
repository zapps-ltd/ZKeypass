"""Copying secrets to the Windows clipboard without leaving them behind.

Two things go wrong with an ordinary copy of a password:

* Windows clipboard history (Windows key plus V) keeps every copied text,
  and cloud clipboard can upload it to other devices.
* Clearing the clipboard later wipes whatever the user copied since.

copy_secret() marks the text with the formats Windows reads to keep it out
of history, out of the cloud clipboard and away from clipboard monitors, the
same ones KeePass and KeePassXC set.  Clearing only happens when the
clipboard still holds what ZKeypass put there.

Off Windows, or if the Win32 calls fail, the wx clipboard is used instead,
so a copy always works.
"""

import ctypes
import sys

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

_our_sequence = None
_pending = None


def _win32():
    """The user32 and kernel32 calls, typed for 64-bit Windows."""
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    user32.RegisterClipboardFormatW.restype = wintypes.UINT
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = wintypes.LPVOID
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.restype = wintypes.HGLOBAL
    return user32, kernel32


def _global(kernel32, data):
    """Copy bytes into movable global memory, as SetClipboardData wants."""
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, max(1, len(data)))
    if not handle:
        return None
    pointer = kernel32.GlobalLock(handle)
    if not pointer:
        kernel32.GlobalFree(handle)
        return None
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    return handle


def _owner():
    """ZKeypass's own window.  Windows refuses SetClipboardData without one."""
    try:
        import wx

        window = wx.GetApp().GetTopWindow() if wx.GetApp() else None
        return window.GetHandle() if window else None
    except Exception:
        return None


def _open(user32, need_owner=False):
    """OpenClipboard, retried briefly: another program may hold it."""
    import time

    owner = _owner()
    if need_owner and not owner:
        return False
    for _attempt in range(10):
        if user32.OpenClipboard(owner):
            return True
        time.sleep(0.02)
    return False


def _copy_win32(text):
    calls = _win32()
    if calls is None:
        return False
    user32, kernel32 = calls
    if not _open(user32, need_owner=True):
        return False
    try:
        user32.EmptyClipboard()
        body = _global(kernel32, (text + "\0").encode("utf-16-le"))
        if body is None or not user32.SetClipboardData(CF_UNICODETEXT, body):
            if body:
                kernel32.GlobalFree(body)
            return False
        zero = (0).to_bytes(4, "little")
        for name, data in (
            ("ExcludeClipboardContentFromMonitorProcessing", zero),
            ("CanIncludeInClipboardHistory", zero),
            ("CanUploadToCloudClipboard", zero),
        ):
            kind = user32.RegisterClipboardFormatW(name)
            handle = _global(kernel32, data) if kind else None
            if handle and not user32.SetClipboardData(kind, handle):
                kernel32.GlobalFree(handle)
        return True
    finally:
        user32.CloseClipboard()


def _copy_wx(text):
    import wx

    if not wx.TheClipboard.Open():
        return False
    try:
        wx.TheClipboard.SetData(wx.TextDataObject(text))
        return True
    finally:
        wx.TheClipboard.Close()


def _sequence():
    calls = _win32()
    if calls is None:
        return None
    try:
        return int(calls[0].GetClipboardSequenceNumber())
    except Exception:
        return None


def copy_secret(text, clear_after_seconds=0):
    """Copy text, keep it out of clipboard history, clear it later.

    Returns True when the text is on the clipboard.
    """
    global _our_sequence, _pending
    try:
        done = _copy_win32(text)
    except Exception:
        done = False
    if not done:
        done = _copy_wx(text)
    if not done:
        return False
    _our_sequence = _sequence()
    if _pending is not None:
        try:
            _pending.Stop()
        except Exception:
            pass
        _pending = None
    seconds = int(clear_after_seconds or 0)
    if seconds > 0:
        try:
            import wx

            _pending = wx.CallLater(seconds * 1000, clear_if_ours)
        except Exception:
            _pending = None
    return True


def copy_plain(text):
    """Copy ordinary text, such as a report or a pipe name."""
    try:
        if _copy_win32(text):
            return True
    except Exception:
        pass
    return _copy_wx(text)


def holds_ours():
    """True when the clipboard has not changed since ZKeypass copied a secret."""
    if _our_sequence is None:
        return False
    current = _sequence()
    return current is None or current == _our_sequence


def clear(force=True):
    """Empty the clipboard.  With force=False, only if it still holds ours."""
    global _our_sequence
    if not force and not holds_ours():
        _our_sequence = None
        return False
    done = False
    calls = _win32()
    if calls is not None:
        user32 = calls[0]
        if _open(user32):
            try:
                done = bool(user32.EmptyClipboard())
            finally:
                user32.CloseClipboard()
    if not done:
        try:
            import wx

            if wx.TheClipboard.Open():
                wx.TheClipboard.Clear()
                wx.TheClipboard.Close()
                done = True
        except Exception:
            pass
    _our_sequence = None
    return done


def clear_if_ours():
    """The timed clear: leaves alone anything the user copied since."""
    global _pending
    _pending = None
    return clear(force=False)
