"""The screens around Windows Hello: waiting, offering it, opening with it.

winhello.py does the work and knows nothing about windows.  This module
shows the small "waiting for Windows Hello" dialog while that work runs on
a worker thread, asks whether to use Windows Hello next time, and opens a
database with it.  Every dialog is an ordinary wx dialog, so NVDA and JAWS
read it, and the Windows Hello prompt itself is Windows' own.
"""

import threading

import wx

from . import winhello
from . import lang

ID_USE_HELLO = wx.NewIdRef()


class WaitingDialog(wx.Dialog):
    """Says what is happening while Windows Hello is on screen."""

    def __init__(self, parent, message):
        super().__init__(parent, title=lang.t(
            "dialogs", "windows_hello",
            "Windows Hello"))
        text = wx.StaticText(self, label=message)
        text.Wrap(440)
        cancel = wx.Button(self, id=wx.ID_CANCEL, label=lang.control_label(
            "cancel",
            "&Cancel"))
        cancel.Bind(wx.EVT_BUTTON, self.on_cancel)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(text, 0, wx.ALL, 14)
        root.Add(cancel, 0, wx.ALIGN_RIGHT | wx.ALL, 10)
        self.SetSizerAndFit(root)
        self.Bind(wx.EVT_CLOSE, self.on_cancel)
        cancel.SetFocus()

    def on_cancel(self, event=None):
        winhello.cancel_current()


def run_waiting(parent, message, work):
    """Run work() on a worker thread with the waiting dialog up.

    Returns work()'s result, or raises the exception it raised.
    """
    outcome = {}
    dialog = WaitingDialog(parent, message)

    def worker():
        try:
            outcome["value"] = work()
        except BaseException as error:  # handed back to the main thread
            outcome["error"] = error
        wx.CallAfter(finish)

    def finish():
        if dialog.IsModal():
            dialog.EndModal(wx.ID_OK)

    thread = threading.Thread(target=worker, daemon=True)
    wx.CallAfter(thread.start)
    dialog.ShowModal()
    thread.join(1)
    dialog.Destroy()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def can_offer(path, challenge_response=None):
    """Whether this database may use Windows Hello at all."""
    return bool(path) and not challenge_response and winhello.available()[0]


def try_open(parent, path):
    """Open the database with Windows Hello.

    Returns (vault, PasswordPair) on success, or None when the password has
    to be typed instead; any reason is shown in a message first, except a
    plain Cancel.
    """
    if not winhello.is_set_up(path):
        # A copy of a database from an older ZKPass folder brings its Windows
        # Hello record along; any trouble there just means the password.
        try:
            winhello.adopt_older(path)
        except Exception:
            pass
    if not winhello.is_set_up(path):
        return None
    from .kdbx_vault import open_any
    from .vault import PasswordPair

    try:
        password, keyfile = run_waiting(
            parent, lang.t(
                "dialogs", "confirm_it_is_you_in_the",
                "Confirm it is you in the Windows Hello window, with your "
                "PIN, fingerprint or face. Cancel to type the master "
                "password instead."),
            lambda: winhello.unlock(path))
    except winhello.HelloCancelled:
        return None
    except winhello.HelloError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "windows_hello",
            "Windows Hello"),
                      wx.OK | wx.ICON_INFORMATION, parent)
        return None
    try:
        vault = open_any(path, password, keyfile, None)
    except Exception:
        winhello.forget(path)
        wx.MessageBox(
            lang.t(
                "errors", "windows_hello_worked_but_the_saved",
                "Windows Hello worked, but the saved master password no "
                "longer opens this database; it may have been changed in "
                "another program. Type the master password, and you can set "
                "Windows Hello up again."), lang.t(
                "dialogs", "windows_hello",
                "Windows Hello"),
            wx.OK | wx.ICON_INFORMATION, parent)
        return None
    return vault, PasswordPair(password, keyfile)


def turn_on(parent, path, password, keyfile=None):
    """Seal the password with Windows Hello now.  True when it worked."""
    try:
        run_waiting(parent, lang.t(
            "dialogs", "confirm_it_is_you_in_the_2",
            "Confirm it is you in the Windows Hello window, with your PIN, "
            "fingerprint or face."),
                    lambda: winhello.enroll(path, password, keyfile))
    except winhello.HelloCancelled:
        return False
    except winhello.HelloError as error:
        wx.MessageBox(str(error), lang.t(
            "dialogs", "windows_hello",
            "Windows Hello"),
                      wx.OK | wx.ICON_WARNING, parent)
        return False
    wx.MessageBox(
        lang.t(
            "errors", "windows_hello_is_on_for_this",
            "Windows Hello is on for this database. Next time, confirm with "
            "your PIN, fingerprint or face instead of typing the master "
            "password.\n\nKeep remembering the master password: it is still "
            "needed on other computers, and if Windows Hello is reset."),
        lang.t("dialogs", "windows_hello", "Windows Hello"), wx.OK | wx.ICON_INFORMATION, parent)
    return True


def unlock_loop(parent, path, dialog_class, tries=3):
    """Open a database: Windows Hello first when set up, else the password.

    dialog_class is the password dialog to show, UnlockDialog in the
    program.  Returns (vault, PasswordPair), or (None, None) when the person
    gives up.  After a typed password works, Windows Hello is offered.
    """
    from .kdbx_vault import open_any
    from .vault import PasswordPair

    opened = try_open(parent, path)
    if opened:
        return opened
    attempt = 0
    while attempt < tries:
        dialog = dialog_class(parent, path)
        result = dialog.ShowModal()
        password = dialog.password
        keyfile = dialog.keyfile
        challenge_response = dialog.challenge_response
        typed = isinstance(dialog, wx.Dialog)
        dialog.Destroy()
        if result == ID_USE_HELLO:
            opened = try_open(parent, path)
            if opened:
                return opened
            continue
        if result != wx.ID_OK:
            return None, None
        attempt += 1
        try:
            vault = open_any(path, password, keyfile, challenge_response)
        except Exception as error:
            wx.MessageBox(str(error), "ZKeypass", wx.OK | wx.ICON_ERROR, parent)
            continue
        pair = PasswordPair(password, keyfile)
        pair.challenge_response = challenge_response
        if typed:
            offer(parent, path, password, keyfile, challenge_response)
        return vault, pair
    return None, None


def offer(parent, path, password, keyfile=None, challenge_response=None):
    """After the password worked: ask once whether to use Windows Hello."""
    if not password or winhello.is_set_up(path) or winhello.was_declined(path):
        return
    if not can_offer(path, challenge_response):
        return
    dialog = wx.MessageDialog(
        parent,
        lang.t(
            "dialogs", "open_this_database_with_windows_hello",
            "Open this database with Windows Hello next time?\n\nYou would "
            "confirm with your PIN, fingerprint or face instead of typing "
            "the master password. It works only on this computer and in this "
            "Windows account."),
        lang.t("dialogs", "windows_hello", "Windows Hello"), wx.YES_NO | wx.CANCEL | wx.ICON_QUESTION)
    dialog.SetYesNoCancelLabels(lang.control_label(
        "use_windows_hello",
        "&Use Windows Hello"), lang.control_label(
        "not_now",
        "&Not now"),
                                lang.control_label(
                                    "never_for_this_database",
                                    "N&ever for this database"))
    answer = dialog.ShowModal()
    dialog.Destroy()
    if answer == wx.ID_YES:
        turn_on(parent, path, password, keyfile)
    elif answer == wx.ID_CANCEL:
        winhello.set_declined(path, True)
