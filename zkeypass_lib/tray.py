"""ZKeypass in the notification area, with its logo animated.

The icon is the logo: teal while a database is open, amber while ZKeypass is
locked, with the spark running round the shield every few seconds.  Its
tooltip, which screen readers read as the icon's name, says which.

Click it, or press Enter on it, to show ZKeypass.  Right click, the
Applications key or Shift+F10 opens its menu: Show ZKeypass, Settings and
Quit.  Windows reaches the notification area from the keyboard with
Windows+B.
"""

import ctypes
import time

import wx
import wx.adv

from . import logo, theme
from . import lang

ID_SHOW = wx.NewIdRef()
ID_SETTINGS = wx.NewIdRef()
ID_QUIT = wx.NewIdRef()


def _icon_size():
    try:
        return max(16, ctypes.windll.user32.GetSystemMetrics(49))  # SM_CXSMICON
    except Exception:
        return 16


class Tray(wx.adv.TaskBarIcon):
    SWEEP = 1.6
    REST = 4.0
    FRAMES = 24

    def __init__(self, app):
        super().__init__()
        self.app = app
        self.locked = True
        self.name = ""
        self.size = _icon_size()
        self.frames = {}
        self.shown = None
        self.started = time.perf_counter()
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.on_tick, source=self.timer)
        self.Bind(wx.adv.EVT_TASKBAR_LEFT_UP, lambda event: self.app.show())
        self.Bind(wx.adv.EVT_TASKBAR_LEFT_DCLICK, lambda event: self.app.show())
        self.Bind(wx.EVT_MENU, lambda event: self.app.show(), id=ID_SHOW)
        self.Bind(wx.EVT_MENU, lambda event: self.app.open_settings(), id=ID_SETTINGS)
        self.Bind(wx.EVT_MENU, lambda event: self.app.quit(), id=ID_QUIT)
        self.update(force=True)
        self.timer.Start(66)

    # ------------------------------------------------------------- state

    def tooltip(self):
        if self.locked:
            return lang.t(
                "dialogs", "zkeypass_locked_choose_show_zkeypass_to",
                "ZKeypass - locked. Choose Show ZKeypass to unlock.")
        return lang.t(
            "dialogs", "zkeypass_is_open",
            "ZKeypass - {name} is open",
            name=self.name) if self.name else lang.t(
            "dialogs", "zkeypass_open",
            "ZKeypass - open")

    def set_locked(self, locked, name=""):
        self.locked = bool(locked)
        self.name = "" if locked else name
        self.update(force=True)

    # --------------------------------------------------------- animation

    def _frame(self, phase):
        key = (self.locked, None if phase is None else int(phase * self.FRAMES))
        if key not in self.frames:
            self.frames[key] = logo.icon(
                self.size, None if phase is None else key[1] / self.FRAMES,
                locked=self.locked)
        return key, self.frames[key]

    def _phase(self):
        if not theme.effects_enabled():
            return None
        cycle = (time.perf_counter() - self.started) % (self.SWEEP + self.REST)
        return None if cycle >= self.SWEEP else cycle / self.SWEEP

    def update(self, force=False):
        key, icon = self._frame(self._phase())
        if force or key != self.shown:
            self.shown = key
            try:
                self.SetIcon(icon, self.tooltip())
            except Exception:
                pass

    def on_tick(self, event):
        self.update()

    # -------------------------------------------------------------- menu

    def CreatePopupMenu(self):
        menu = wx.Menu()
        # While locked, Show ZKeypass asks for Windows Hello or the password.
        menu.Append(ID_SHOW, lang.menu_label("show_zkeypass", "&Show ZKeypass"))
        menu.Append(ID_SETTINGS, lang.menu_label("settings", "S&ettings..."))
        menu.AppendSeparator()
        menu.Append(ID_QUIT, lang.menu_label("quit_zkeypass", "&Quit ZKeypass"))
        return menu

    def close(self):
        self.timer.Stop()
        try:
            self.RemoveIcon()
        except Exception:
            pass
        self.Destroy()
