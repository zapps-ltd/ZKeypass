"""The look of ZKeypass: a dark, high-tech theme that stays a native one.

Everything the keyboard and the screen reader touch is still an ordinary
Windows control.  The theme only changes colours and adds decoration:

    Dark mode   wxWidgets' own Windows dark mode, with ZKeypass's navy and
                teal palette given to it through DarkModeSettings, so menus,
                lists, tabs, buttons and the title bar all follow it.
    Banner      a painted strip with the animated logo at the top of the
                main window and the first windows; it never takes the focus.
                Every spoken action also lights up on it for a moment.
    Fade        windows and dialogs fade in over a fraction of a second.
    Focus glow  a soft teal ring eases in round whichever control has the
                focus, so sighted users can follow the keyboard too.

Nothing is themed when Windows high contrast is on, and nothing moves when
Settings, Look and start, turns "Smooth visual effects" off.
"""

import ctypes
import time
import weakref

import wx

from . import logo
from . import lang

# Palette.  Text on the background is about 14 to 1, the muted text about 7
# to 1, so both read comfortably without the glare of pure white on black.
BACKGROUND = wx.Colour(13, 21, 38)
SURFACE = wx.Colour(17, 27, 46)
SURFACE_RAISED = wx.Colour(24, 37, 60)
BORDER = wx.Colour(35, 50, 77)
TEXT = wx.Colour(220, 230, 242)
MUTED = wx.Colour(143, 163, 191)
DISABLED = wx.Colour(100, 117, 142)
ACCENT = wx.Colour(*logo.TEAL)
ACCENT_2 = wx.Colour(*logo.BLUE)
SELECTION = wx.Colour(15, 76, 92)
MENU_HOT = wx.Colour(19, 78, 94)

_state = {"dark": False, "effects": True, "installed": False}
_dark_settings = None
_original_show_modal = None
_original_message_box = None
_original_text_entry = None


# ------------------------------------------------------------------ queries

def high_contrast():
    """Whether Windows high contrast is on; the theme then stays out of the way."""
    class HighContrast(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwFlags", ctypes.c_uint),
                    ("lpszDefaultScheme", ctypes.c_wchar_p)]

    try:
        info = HighContrast()
        info.cbSize = ctypes.sizeof(HighContrast)
        if ctypes.windll.user32.SystemParametersInfoW(0x0042, info.cbSize,
                                                      ctypes.byref(info), 0):
            return bool(info.dwFlags & 0x1)
    except Exception:
        pass
    return False


def is_dark():
    return _state["dark"]


def effects_enabled():
    """Settings, Look and start, "Smooth visual effects" decides, on at first.

    Windows' own "Show animations" switch is not followed: it is often off on
    computers set up for a screen reader whose owner still wants these.
    """
    return _state["effects"]


# ---------------------------------------------------------------- dark mode

class _Palette(getattr(wx, "DarkModeSettings", object)):
    """Hands ZKeypass's colours to wxWidgets' dark mode."""

    _COLOURS = {
        wx.SYS_COLOUR_WINDOW: SURFACE,
        wx.SYS_COLOUR_LISTBOX: SURFACE,
        wx.SYS_COLOUR_BTNFACE: BACKGROUND,
        wx.SYS_COLOUR_3DFACE: BACKGROUND,
        wx.SYS_COLOUR_APPWORKSPACE: BACKGROUND,
        wx.SYS_COLOUR_WINDOWTEXT: TEXT,
        wx.SYS_COLOUR_BTNTEXT: TEXT,
        wx.SYS_COLOUR_LISTBOXTEXT: TEXT,
        wx.SYS_COLOUR_CAPTIONTEXT: TEXT,
        wx.SYS_COLOUR_MENUTEXT: TEXT,
        wx.SYS_COLOUR_INFOTEXT: TEXT,
        wx.SYS_COLOUR_INFOBK: SURFACE_RAISED,
        wx.SYS_COLOUR_GRAYTEXT: DISABLED,
        wx.SYS_COLOUR_HIGHLIGHT: SELECTION,
        wx.SYS_COLOUR_HIGHLIGHTTEXT: wx.Colour(255, 255, 255),
        wx.SYS_COLOUR_HOTLIGHT: ACCENT,
        wx.SYS_COLOUR_MENU: SURFACE,
        wx.SYS_COLOUR_MENUBAR: BACKGROUND,
        wx.SYS_COLOUR_MENUHILIGHT: MENU_HOT,
        wx.SYS_COLOUR_BTNSHADOW: BORDER,
        wx.SYS_COLOUR_3DDKSHADOW: BORDER,
        wx.SYS_COLOUR_3DLIGHT: BORDER,
        wx.SYS_COLOUR_BTNHIGHLIGHT: SURFACE_RAISED,
        wx.SYS_COLOUR_ACTIVEBORDER: BORDER,
        wx.SYS_COLOUR_INACTIVEBORDER: BORDER,
        wx.SYS_COLOUR_LISTBOXHIGHLIGHTTEXT: wx.Colour(255, 255, 255),
    }

    def GetColour(self, index):
        colour = self._COLOURS.get(index)
        return wx.Colour(colour) if colour is not None else super().GetColour(index)

    def GetMenuColour(self, which):
        return {
            wx.MenuColour.StandardFg: TEXT,
            wx.MenuColour.StandardBg: BACKGROUND,
            wx.MenuColour.DisabledFg: DISABLED,
            wx.MenuColour.HotBg: MENU_HOT,
        }.get(which, TEXT)

    def GetBorderPen(self):
        return wx.Pen(BORDER)


def install(app, settings):
    """Turn the theme on for the whole program.  Call before any window exists."""
    global _dark_settings, _original_show_modal
    _state["effects"] = bool(settings.get("visual_effects", True))
    wanted = (settings.get("theme") or "dark") == "dark"
    if wanted and not high_contrast() and hasattr(app, "MSWEnableDarkMode"):
        try:
            _dark_settings = _Palette()
            _state["dark"] = bool(app.MSWEnableDarkMode(
                wx.App.DarkMode_Always, _dark_settings))
        except Exception:
            _state["dark"] = False
    if not _state["installed"]:
        _state["installed"] = True
        _original_show_modal = wx.Dialog.ShowModal

        def show_modal(dialog):
            if lang.is_rtl() and \
                    dialog.GetLayoutDirection() != wx.Layout_RightToLeft:
                dialog.SetLayoutDirection(wx.Layout_RightToLeft)
                dialog.Layout()
            prepare(dialog)
            return _original_show_modal(dialog)

        wx.Dialog.ShowModal = show_modal

        # Windows' own message and text-entry boxes are native task dialogs
        # that stay light in the dark theme.  Replace them with ordinary wx
        # dialogs, which the ShowModal patch above themes and fades like every
        # other window.  The replacements keep wx.MessageBox's return values
        # and are used only while the dark theme is really on; under the light
        # or high-contrast theme the originals are left in place.
        global _original_message_box, _original_text_entry
        _original_message_box = wx.MessageBox
        _original_text_entry = wx.GetTextFromUser
        wx.MessageBox = message_box
        wx.GetTextFromUser = text_entry


def set_effects(enabled):
    _state["effects"] = bool(enabled)


# ------------------------------------------------------------- per window

def prepare(window, fade=True):
    """Theme a window that is about to be shown: colours, glow, fade."""
    try:
        if not window.GetHandle():
            return  # a Windows common dialog with no wx window of its own
    except Exception:
        return
    if getattr(window, "_zk_prepared", False):
        return
    window._zk_prepared = True
    try:
        if not isinstance(window, wx.Dialog) or not window.GetIcon().IsOk():
            window.SetIcons(_bundle())
    except Exception:
        pass
    if not high_contrast():
        style_tree(window)
        FocusGlow(window)
    if fade:
        fade_in(window)


_icons = {}


def _bundle():
    if "bundle" not in _icons:
        _icons["bundle"] = logo.icon_bundle()
    return _icons["bundle"]


def style_tree(window):
    """Finish what dark mode leaves grey: notebook pages and lists turn navy,
    and bold captions, the headings, turn teal."""
    if not _state["dark"]:
        return
    for child in window.GetChildren():
        if isinstance(child, wx.StaticText):
            if child.GetFont().GetWeight() >= wx.FONTWEIGHT_BOLD:
                child.SetForegroundColour(ACCENT)
        elif isinstance(child, (wx.ListCtrl, wx.ListBox)):
            child.SetBackgroundColour(SURFACE)
            child.SetForegroundColour(TEXT)
        elif isinstance(child, wx.Notebook):
            child.SetBackgroundColour(BACKGROUND)
            style_tree(child)
        elif isinstance(child, wx.Panel) and not isinstance(child, Banner):
            if isinstance(window, wx.Notebook):
                child.SetBackgroundColour(BACKGROUND)
            style_tree(child)


def _ease(t):
    """Ease out: quick at first, settling gently."""
    t = max(0.0, min(1.0, t))
    return 1 - (1 - t) ** 3


def _alive(window):
    """True while a window exists and is not being torn down."""
    try:
        return bool(window) and not window.IsBeingDeleted()
    except Exception:
        return False


# ---------------------------------------------------------------- animator

class _Animator:
    """One timer for every animation in ZKeypass, created once, never freed.

    Each fade, focus ring and banner registers a step function here instead
    of owning a wx.Timer.  A timer tied to a window, or kept in a reference
    loop with one, can be freed by Python's garbage collector at a random
    moment after the window is gone, and that corrupts memory.  A step
    function returns False when it is finished or its window has gone, and
    is then dropped.
    """

    INTERVAL = 16

    def __init__(self):
        self.timer = None
        self.steps = {}

    def add(self, key, step):
        self.steps[key] = step
        if self.timer is None:
            self.timer = wx.Timer()
            self.timer.Bind(wx.EVT_TIMER, self.on_tick)
        if not self.timer.IsRunning():
            self.timer.Start(self.INTERVAL)

    def running(self, key):
        return key in self.steps

    def on_tick(self, event):
        for key, step in list(self.steps.items()):
            try:
                keep = step()
            except Exception:
                keep = False
            if not keep:
                self.steps.pop(key, None)
        if not self.steps:
            self.timer.Stop()


_animator = _Animator()


def fade_in(window, duration=170):
    """Fade a top-level window in.  It is fully opaque again in any case."""
    if not effects_enabled():
        return
    try:
        if not window.CanSetTransparent() or not window.SetTransparent(0):
            return
    except Exception:
        return
    started = time.perf_counter()
    handle = weakref.ref(window)

    def step():
        target = handle()
        if not _alive(target):
            return False
        progress = (time.perf_counter() - started) * 1000 / duration
        try:
            target.SetTransparent(255 if progress >= 1
                                  else int(255 * _ease(progress)))
        except Exception:
            return False
        return progress < 1

    def finish():
        # However the fade went, the window ends fully opaque.
        target = handle()
        if _alive(target):
            try:
                target.SetTransparent(255)
            except Exception:
                pass

    _animator.add(("fade", id(window)), step)
    wx.CallLater(duration + 400, finish)


def is_fading(window):
    return _animator.running(("fade", id(window)))


# -------------------------------------------------------------- focus glow

_glows = weakref.WeakValueDictionary()


def has_glow(window):
    return id(window) in _glows


class FocusGlow:
    """A teal ring that eases in round the focused control.

    The ring is painted by the control's parent in the margin the sizer
    leaves round it, so the control itself is never touched.  The glow is
    kept alive only by the event handlers bound to its window and refers
    to that window weakly, so the two never form a reference loop.
    """

    STEP = 0.12

    def __init__(self, window):
        self.window = weakref.ref(window)
        self.target = None
        self.level = 0.0
        self.previous = None
        self.previous_level = 0.0
        # Every panel that may paint a ring is hooked once, now: hooking one
        # later, from a focus change, can happen while a closing dialog is
        # being torn down.
        self.containers = set()
        self._hook(window)
        window.Bind(wx.EVT_CHILD_FOCUS, self.on_focus)
        window.Bind(wx.EVT_WINDOW_DESTROY, self.on_destroy)
        _glows[id(window)] = self

    def _hook(self, window):
        if self._is_container(window):
            window.Bind(wx.EVT_PAINT, self.on_paint)
            self.containers.add(id(window))
        for child in window.GetChildren():
            if not child.IsTopLevel():
                self._hook(child)

    @staticmethod
    def _is_container(window):
        return (isinstance(window, (wx.Panel, wx.Dialog))
                and not isinstance(window, (wx.Notebook, Banner)))

    def on_destroy(self, event):
        if event.GetEventObject() is self.window():
            self.target = self.previous = None
            self.level = self.previous_level = 0.0
        event.Skip()

    def _container(self, window):
        """The control to ring, and the hooked panel that paints round it."""
        target = window
        while target is not None and not target.IsTopLevel():
            parent = target.GetParent()
            if not _alive(parent):
                return None
            if id(parent) in self.containers:
                return target
            target = parent
        return None

    def on_focus(self, event):
        event.Skip()
        window = self.window()
        if not _alive(window):
            return
        try:
            focus = wx.Window.FindFocus()
            # Focus that has moved to another window, such as the main
            # window behind a closing dialog, is that window's business.
            if not _alive(focus) or wx.GetTopLevelParent(focus) is not window:
                target = None
            else:
                target = self._container(focus)
        except Exception:
            return
        if target is self.target:
            return
        self._refresh(self.previous)
        self.previous, self.previous_level = self.target, self.level
        self.target, self.level = target, 0.0
        if effects_enabled():
            _animator.add(("glow", id(window)), self.step)
        else:
            self.level, self.previous_level = 1.0, 0.0
            self._refresh(self.previous)
            self._refresh(self.target)

    def step(self):
        if not _alive(self.window()):
            return False
        self.level = min(1.0, self.level + self.STEP)
        self.previous_level = max(0.0, self.previous_level - self.STEP)
        self._refresh(self.target)
        self._refresh(self.previous)
        return self.level < 1.0 or self.previous_level > 0.0

    @staticmethod
    def _shown(window):
        try:
            return _alive(window) and window.IsShown()
        except Exception:
            return False

    def _refresh(self, target):
        if not self._shown(target):
            return
        try:
            rect = target.GetRect().Inflate(8, 8)
            target.GetParent().RefreshRect(rect, True)
        except Exception:
            pass

    def on_paint(self, event):
        container = event.GetEventObject()
        dc = wx.PaintDC(container)
        if not _alive(self.window()):
            return
        try:
            gc = wx.GraphicsContext.Create(dc)
        except Exception:
            return
        try:
            self._draw(gc, container)
        finally:
            # The graphics context must go before the DC it draws on, or it
            # flushes into a DC that has already been freed.
            del gc

    def _draw(self, gc, container):
        for target, level in ((self.previous, self.previous_level),
                              (self.target, self.level)):
            if level <= 0 or not self._shown(target):
                continue
            try:
                if target.GetParent() is not container:
                    continue
                rect = target.GetRect()
            except Exception:
                continue
            strength = _ease(level)
            gc.SetBrush(wx.TRANSPARENT_BRUSH)
            gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(wx.Colour(
                ACCENT.Red(), ACCENT.Green(), ACCENT.Blue(), int(55 * strength)))
                .Width(5)))
            gc.DrawRoundedRectangle(rect.x - 4, rect.y - 4, rect.width + 8,
                                    rect.height + 8, 6)
            gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(wx.Colour(
                ACCENT.Red(), ACCENT.Green(), ACCENT.Blue(), int(220 * strength)))
                .Width(1.5)))
            gc.DrawRoundedRectangle(rect.x - 2.5, rect.y - 2.5, rect.width + 5,
                                    rect.height + 5, 5)


# ------------------------------------------------------------------ banner

class Banner(wx.Window):
    """The strip at the top: animated logo, name, a line of context, and the
    latest action lighting up on the right.  Decoration only: it never takes
    the focus, and everything it shows is also on the status bar or spoken.
    """

    SWEEP = 1.6     # seconds the spark takes round the shield
    REST = 5.0      # seconds the logo then rests
    FRAMES = 40
    FRAME_TIME = 0.05

    def __init__(self, parent, subtitle="", locked=False):
        super().__init__(parent, style=wx.BORDER_NONE)
        self.SetBackgroundStyle(wx.BG_STYLE_PAINT)
        self.SetMinSize((-1, self.FromDIP(68)))
        self.subtitle = subtitle
        self.locked = locked
        self.action_text = ""
        self.pulse_level = 0.0
        self.started = time.perf_counter()
        self.last_frame = 0.0
        self.logo_size = self.FromDIP(46)
        self.still = logo.bitmap(self.logo_size, locked=locked)
        self.frames = {}
        self.Bind(wx.EVT_PAINT, self.on_paint)
        self.Bind(wx.EVT_SIZE, lambda event: (self.Refresh(), event.Skip()))
        self.animate()

    def AcceptsFocus(self):
        return False

    def AcceptsFocusFromKeyboard(self):
        return False

    def animate(self):
        """Join the shared animation timer, holding this banner weakly."""
        if not effects_enabled():
            return
        handle = weakref.ref(self)

        def step():
            banner = handle()
            return banner.on_tick() if _alive(banner) else False

        _animator.add(("banner", id(self)), step)

    def set_subtitle(self, text):
        self.subtitle = text
        self.Refresh()

    def pulse(self, text):
        """Light up the latest action."""
        self.action_text = text
        self.pulse_level = 1.0 if effects_enabled() else 0.0
        self.animate()
        self.Refresh()

    def _phase(self):
        cycle = (time.perf_counter() - self.started) % (self.SWEEP + self.REST)
        if cycle >= self.SWEEP:
            return None
        return cycle / self.SWEEP

    def _logo(self, phase):
        if phase is None:
            return self.still
        frame = int(phase * self.FRAMES) % self.FRAMES
        if frame not in self.frames:
            self.frames[frame] = logo.bitmap(self.logo_size, frame / self.FRAMES,
                                             locked=self.locked)
        return self.frames[frame]

    def on_tick(self):
        """One step of the banner's animation.  False ends it."""
        if not effects_enabled():
            self.pulse_level = 0.0
            self.Refresh(False)
            return False
        now = time.perf_counter()
        if now - self.last_frame < self.FRAME_TIME:
            return True
        self.last_frame = now
        try:
            if not self.IsShownOnScreen():
                return True
        except Exception:
            return False
        if self.pulse_level > 0:
            self.pulse_level = max(0.0, self.pulse_level - 0.025)
        self.Refresh(False)
        return True

    def on_paint(self, event):
        dc = wx.AutoBufferedPaintDC(self)
        gc = wx.GraphicsContext.Create(dc)
        try:
            self._draw(gc)
        finally:
            del gc  # before the DC, see FocusGlow.on_paint

    def _draw(self, gc):
        width, height = self.GetClientSize()
        gc.SetBrush(gc.CreateLinearGradientBrush(
            0, 0, width, 0, wx.Colour(10, 17, 31), wx.Colour(18, 31, 52)))
        gc.SetPen(wx.TRANSPARENT_PEN)
        gc.DrawRectangle(0, 0, width, height)

        # A faint grid, like a circuit board seen from far away.
        gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(wx.Colour(45, 226, 201, 14))))
        step = self.FromDIP(18)
        for x in range(0, width, step):
            gc.StrokeLine(x, 0, x, height)
        for y in range(0, height, step):
            gc.StrokeLine(0, y, width, y)

        # The bottom edge, with a highlight travelling along it.
        phase = self._phase() if effects_enabled() else None
        gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo().Width(2).LinearGradient(
            0, 0, width, 0, wx.Colour(45, 226, 201, 150),
            wx.Colour(59, 130, 246, 60))))
        gc.StrokeLine(0, height - 1, width, height - 1)
        if phase is not None:
            centre = phase * width
            glow = gc.CreateRadialGradientBrush(
                centre, height - 1, centre, height - 1, width * 0.12,
                wx.Colour(230, 255, 251, 200), wx.Colour(45, 226, 201, 0))
            gc.SetBrush(glow)
            gc.SetPen(wx.TRANSPARENT_PEN)
            gc.DrawRectangle(centre - width * 0.12, height - 3, width * 0.24, 3)

        margin = self.FromDIP(14)
        top = (height - self.logo_size) // 2
        gc.DrawBitmap(self._logo(phase), margin, top, self.logo_size, self.logo_size)

        left = margin * 2 + self.logo_size
        title_font = wx.Font(wx.FontInfo(16).FaceName("Segoe UI Semibold"))
        gc.SetFont(gc.CreateFont(title_font, TEXT))
        _w, title_height = gc.GetTextExtent("ZKeypass")
        gc.DrawText("ZKeypass", left, height / 2 - title_height + self.FromDIP(3))
        gc.SetFont(gc.CreateFont(wx.Font(wx.FontInfo(9).FaceName("Segoe UI")),
                                 MUTED))
        gc.DrawText(self.subtitle, left, height / 2 + self.FromDIP(2))

        if self.action_text:
            self._paint_action(gc, width, height)

    def _paint_action(self, gc, width, height):
        font = wx.Font(wx.FontInfo(9).FaceName("Segoe UI Semibold"))
        text = self.action_text
        available = max(80, int(width * 0.45))
        gc.SetFont(gc.CreateFont(font, TEXT))
        while len(text) > 8 and gc.GetTextExtent(text)[0] > available - 28:
            text = text[:-2]
        if text != self.action_text:
            text = text.rstrip(" .,") + "…"
        text_width, text_height = gc.GetTextExtent(text)
        chip_w, chip_h = text_width + 28, text_height + 12
        x = width - chip_w - self.FromDIP(14)
        y = (height - chip_h) / 2
        glow = _ease(self.pulse_level)
        gc.SetBrush(wx.Brush(wx.Colour(24, 37, 60, 230)))
        gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(wx.Colour(
            45, 226, 201, int(70 + 185 * glow))).Width(1 + 1.5 * glow)))
        gc.DrawRoundedRectangle(x, y, chip_w, chip_h, chip_h / 2)
        dot = 3 + 2 * glow
        gc.SetPen(wx.TRANSPARENT_PEN)
        gc.SetBrush(wx.Brush(wx.Colour(45, 226, 201, int(150 + 105 * glow))))
        gc.DrawEllipse(x + 11 - dot, y + chip_h / 2 - dot, dot * 2, dot * 2)
        shade = int(170 + 85 * glow)
        gc.SetFont(gc.CreateFont(font, wx.Colour(shade, min(255, shade + 10), 255)))
        gc.DrawText(text, x + 20, y + 6)


# ------------------------------------------------- themed message and prompt
#
# wx.MessageBox and wx.GetTextFromUser open native Windows task dialogs that
# do not follow the dark theme.  These replacements are plain wx.Dialogs, so
# the ShowModal patch themes and fades them, and every control in them is a
# native control a screen reader reads.  The message is spoken when the box
# opens, as the native task dialog's main instruction would be, and it also
# sits in a read-only multiline box the keyboard can reach and re-read.

# wx.MessageBox return values keyed by the control id ShowModal gives back.
_MESSAGE_RESULTS = {
    getattr(wx, "ID_YES", 5103): getattr(wx, "YES", 2),
    getattr(wx, "ID_NO", 5104): getattr(wx, "NO", 8),
    getattr(wx, "ID_OK", 5100): getattr(wx, "OK", 4),
    getattr(wx, "ID_CANCEL", 5101): getattr(wx, "CANCEL", 16),
}


def _message_header(dialog, caption):
    """A compact banner-like strip: the logo and the caption, no focus."""
    panel = Banner(dialog, caption or "ZKeypass")
    panel.SetMinSize((-1, dialog.FromDIP(54)))
    return panel


class ThemedMessageDialog(wx.Dialog):
    """A themed stand-in for the native message box.  Keyboard and screen
    reader reach it as ordinary buttons and a read-only text box."""

    def __init__(self, parent, message, caption, style):
        super().__init__(parent if _alive(parent) else None,
                         title=caption or "ZKeypass")
        self.message = message or ""

        header = _message_header(self, caption or "ZKeypass")
        body = wx.TextCtrl(
            self, value=self.message,
            style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_NO_VSCROLL
                  | wx.BORDER_NONE)
        body.SetName(caption or lang.t("dialogs", "message", "Message"))

        buttons, default_id, escape_id = self._make_buttons(style)

        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(header, 0, wx.EXPAND)
        root.Add(body, 1, wx.EXPAND | wx.ALL, 14)
        root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.LEFT | wx.RIGHT | wx.BOTTOM, 14)
        self.SetSizer(root)
        self._fit(body)

        self.SetAffirmativeId(default_id)
        self.SetEscapeId(escape_id)
        self.FindWindowById(default_id, self).SetDefault()
        self.Bind(wx.EVT_SHOW, self._on_show)

    def _make_buttons(self, style):
        """Yes/No, or OK, with Cancel when asked; match wx.MessageBox flags."""
        row = wx.BoxSizer(wx.HORIZONTAL)
        specs = []
        if style & wx.YES_NO:
            specs.append((wx.ID_YES, lang.control_label("yes", "&Yes")))
            specs.append((wx.ID_NO, lang.control_label("no", "&No")))
        else:
            specs.append((wx.ID_OK, "OK"))
        if style & wx.CANCEL:
            specs.append((wx.ID_CANCEL, lang.t("dialogs", "cancel_2", "Cancel")))
        for ident, label in specs:
            button = wx.Button(self, ident, label)
            button.Bind(wx.EVT_BUTTON, lambda event, i=ident: self.EndModal(i))
            row.Add(button, 0, wx.LEFT, 8)

        ids = [ident for ident, _label in specs]
        if style & wx.NO_DEFAULT and wx.ID_NO in ids:
            default_id = wx.ID_NO
        elif style & wx.CANCEL_DEFAULT and wx.ID_CANCEL in ids:
            default_id = wx.ID_CANCEL
        else:
            default_id = ids[0]
        escape_id = wx.ID_CANCEL if wx.ID_CANCEL in ids else \
            (wx.ID_NO if wx.ID_NO in ids else ids[0])
        return row, default_id, escape_id

    def _fit(self, body):
        """Size to the text, within sensible limits, like a message box."""
        width = self.FromDIP(300)
        line_height = body.GetCharHeight() or self.FromDIP(16)
        dc = wx.ClientDC(body)
        longest = max((dc.GetTextExtent(line)[0]
                       for line in self.message.splitlines() or [""]), default=0)
        width = max(width, min(self.FromDIP(560), longest + self.FromDIP(40)))
        lines = sum(max(1, (dc.GetTextExtent(line)[0] // max(1, width)) + 1)
                    for line in self.message.splitlines() or [""])
        lines = max(1, min(14, lines))
        body.SetMinSize((width, line_height * lines + self.FromDIP(12)))
        self.GetSizer().Fit(self)
        self.SetMinSize(self.GetSize())
        self.CentreOnParent()

    def _on_show(self, event):
        event.Skip()
        if event.IsShown() and self.message:
            from . import speech

            try:
                speech.speak(self.message, window=self)
            except Exception:
                pass


class ThemedTextEntryDialog(wx.Dialog):
    """A themed stand-in for wx.GetTextFromUser: a named box and OK/Cancel."""

    def __init__(self, parent, message, caption, default_value):
        super().__init__(parent if _alive(parent) else None,
                         title=caption or "ZKeypass")
        prompt = wx.StaticText(self, label=message or "")
        prompt.Wrap(self.FromDIP(440))
        self.field = wx.TextCtrl(self, value=default_value or "")
        self.field.SetName(message or caption or lang.t(
            "dialogs", "value",
            "Value"))
        buttons = self.CreateButtonSizer(wx.OK | wx.CANCEL)
        root = wx.BoxSizer(wx.VERTICAL)
        root.Add(prompt, 0, wx.ALL, 14)
        root.Add(self.field, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 14)
        if buttons:
            root.Add(buttons, 0, wx.ALIGN_RIGHT | wx.ALL, 14)
        self.SetSizerAndFit(root)
        self.SetSize(self.FromDIP(wx.Size(480, -1)))
        self.field.SetFocus()
        self.field.SelectAll()
        self.Bind(wx.EVT_TEXT_ENTER, lambda event: self.EndModal(wx.ID_OK))

    def value(self):
        return self.field.GetValue()


def _use_themed_dialogs():
    """Only while the dark theme is really on, and never in high contrast."""
    try:
        return _state["dark"] and bool(wx.GetApp()) and not high_contrast()
    except Exception:
        return False


def message_box(message, caption=None, style=wx.OK | wx.CENTRE,
                parent=None, x=wx.DefaultCoord, y=wx.DefaultCoord):
    """Drop-in for wx.MessageBox that follows the theme.  Falls back to the
    real message box under the light or high-contrast theme, or on any error."""
    if caption is None:
        caption = lang.t("dialogs", "message_caption", "Message")
    if not _use_themed_dialogs():
        return _original_message_box(message, caption, style, parent, x, y)
    try:
        dialog = ThemedMessageDialog(parent, message, caption, style)
    except Exception:
        return _original_message_box(message, caption, style, parent, x, y)
    try:
        result = dialog.ShowModal()
    finally:
        dialog.Destroy()
    return _MESSAGE_RESULTS.get(result, wx.CANCEL)


def text_entry(message, caption=None, default_value="",
               parent=None, x=wx.DefaultCoord, y=wx.DefaultCoord, centre=True):
    """Drop-in for wx.GetTextFromUser; "" when cancelled, as wx does."""
    if caption is None:
        caption = lang.t("dialogs", "please_enter_text", "Please enter text")
    if not _use_themed_dialogs():
        return _original_text_entry(message, caption, default_value, parent,
                                    x, y, centre)
    try:
        dialog = ThemedTextEntryDialog(parent, message, caption, default_value)
    except Exception:
        return _original_text_entry(message, caption, default_value, parent,
                                    x, y, centre)
    try:
        return dialog.value() if dialog.ShowModal() == wx.ID_OK else ""
    finally:
        dialog.Destroy()
