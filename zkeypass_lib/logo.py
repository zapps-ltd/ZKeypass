"""The ZKeypass logo, drawn in code so it can be animated and sized sharply.

The mark is a rounded hexagonal shield with a teal-to-blue edge.  Inside it a
"Z" is drawn as a circuit trace that runs between two terminal nodes, and a
keyhole sits where the trace crosses the middle: zero knowledge, locked.

draw(size, phase) returns a wx.Image with alpha.  phase runs from 0 to 1 and
moves a spark of light once round the shield's edge while the two nodes
breathe; phase None draws the still logo.  locked=True turns the edge, the
spark and the nodes amber, which the tray icon uses while no database is open.

Run  python -m zkeypass_lib.logo  to write assets\\zkeypass.ico and the PNGs the
build and the documentation use.
"""

import math
import os

import wx

# The palette, shared with theme.py.
NAVY_TOP = (19, 35, 59)
NAVY_BOTTOM = (9, 17, 31)
TEAL = (45, 226, 201)
BLUE = (59, 130, 246)
ICE = (230, 255, 251)
AMBER = (245, 165, 36)
ORANGE = (249, 115, 22)

# The shield, a pointy-top hexagon in a 100 by 100 box.
_CENTRE = (50.0, 50.0)
_RADIUS = 45.0
_CORNER = 9.0


def _hexagon():
    points = []
    for index in range(6):
        angle = math.radians(-90 + 60 * index)
        points.append((_CENTRE[0] + _RADIUS * math.cos(angle) * 0.93,
                       _CENTRE[1] + _RADIUS * math.sin(angle)))
    return points


def _perimeter_point(points, fraction):
    """The point a fraction of the way round the hexagon, and its length."""
    edges = [(points[index], points[(index + 1) % 6]) for index in range(6)]
    lengths = [math.dist(start, end) for start, end in edges]
    target = (fraction % 1.0) * sum(lengths)
    for (start, end), length in zip(edges, lengths):
        if target <= length:
            share = target / length
            return (start[0] + (end[0] - start[0]) * share,
                    start[1] + (end[1] - start[1]) * share)
        target -= length
    return points[0]


def _colour(rgb, alpha=255):
    return wx.Colour(rgb[0], rgb[1], rgb[2], int(max(0, min(255, alpha))))


def _shield_path(gc, scale):
    points = [(x * scale, y * scale) for x, y in _hexagon()]
    path = gc.CreatePath()
    first = ((points[0][0] + points[1][0]) / 2, (points[0][1] + points[1][1]) / 2)
    path.MoveToPoint(*first)
    for index in range(1, 7):
        corner = points[index % 6]
        following = points[(index + 1) % 6]
        path.AddArcToPoint(corner[0], corner[1], following[0], following[1],
                           _CORNER * scale)
    path.AddLineToPoint(*first)
    path.CloseSubpath()
    return path


def _paint(gc, size, phase=None, locked=False, detail=True):
    scale = size / 100.0
    spark = AMBER if locked else TEAL
    spark_end = ORANGE if locked else BLUE

    # Shield body.
    shield = _shield_path(gc, scale)
    gc.SetPen(wx.TRANSPARENT_PEN)
    gc.SetBrush(gc.CreateLinearGradientBrush(
        0, 0, 0, size, _colour(NAVY_TOP), _colour(NAVY_BOTTOM)))
    gc.FillPath(shield)

    # Edge: a soft halo, then the crisp gradient line.
    if detail:
        gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(_colour(spark, 40))
                               .Width(max(1.0, 9 * scale))))
        gc.StrokePath(shield)
    edge = wx.GraphicsPenInfo().Width(max(1.0, 5 * scale)).LinearGradient(
        0, 0, size, size, _colour(spark), _colour(spark_end))
    gc.SetPen(gc.CreatePen(edge))
    gc.StrokePath(shield)

    # The spark running round the edge, with a short fading tail.
    if phase is not None:
        points = [(x * scale, y * scale) for x, y in _hexagon()]
        for step in range(8, -1, -1):
            x, y = _perimeter_point(points, phase - step * 0.012)
            fade = 1.0 - step / 9.0
            radius = (1.6 + 2.4 * fade) * scale * (1.15 if detail else 1.0)
            gc.SetBrush(wx.Brush(_colour(ICE if step == 0 else spark,
                                         70 + 185 * fade ** 2)))
            gc.SetPen(wx.TRANSPARENT_PEN)
            gc.DrawEllipse(x - radius, y - radius, radius * 2, radius * 2)

    # The Z, as a circuit trace.
    trace = gc.CreatePath()
    trace.MoveToPoint(31 * scale, 32 * scale)
    trace.AddLineToPoint(69 * scale, 32 * scale)
    trace.AddLineToPoint(33 * scale, 68 * scale)
    trace.AddLineToPoint(69 * scale, 68 * scale)
    if detail:
        gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(_colour(TEAL, 55))
                               .Width(15 * scale).Cap(wx.CAP_ROUND)
                               .Join(wx.JOIN_ROUND)))
        gc.StrokePath(trace)
    z_pen = wx.GraphicsPenInfo().Width(max(1.6, 8.5 * scale)).Cap(
        wx.CAP_ROUND).Join(wx.JOIN_ROUND).LinearGradient(
        0, 25 * scale, 0, 75 * scale, _colour(ICE), _colour(TEAL))
    gc.SetPen(gc.CreatePen(z_pen))
    gc.StrokePath(trace)

    if not detail:
        return

    # Terminal nodes at the two ends of the trace, breathing with the phase.
    glow = 0.65 if phase is None else 0.55 + 0.45 * math.sin(phase * 2 * math.pi)
    for x, y in ((31, 32), (69, 68)):
        outer = 7.5 * scale
        gc.SetPen(wx.TRANSPARENT_PEN)
        gc.SetBrush(wx.Brush(_colour(spark, 60 + 110 * glow)))
        gc.DrawEllipse(x * scale - outer, y * scale - outer, outer * 2, outer * 2)
        inner = 4.6 * scale
        gc.SetBrush(wx.Brush(_colour(ICE)))
        gc.DrawEllipse(x * scale - inner, y * scale - inner, inner * 2, inner * 2)
        core = 2.0 * scale
        gc.SetBrush(wx.Brush(_colour(spark_end)))
        gc.DrawEllipse(x * scale - core, y * scale - core, core * 2, core * 2)

    # The keyhole where the trace crosses the middle.
    gc.SetPen(gc.CreatePen(wx.GraphicsPenInfo(_colour(spark))
                           .Width(max(1.0, 2.2 * scale))))
    gc.SetBrush(wx.Brush(_colour(NAVY_BOTTOM)))
    ring = 8.2 * scale
    gc.DrawEllipse(50 * scale - ring, 46 * scale - ring, ring * 2, ring * 2)
    hole = gc.CreatePath()
    hole.AddCircle(50 * scale, 44.5 * scale, 3.2 * scale)
    hole.MoveToPoint(48.2 * scale, 46 * scale)
    hole.AddLineToPoint(51.8 * scale, 46 * scale)
    hole.AddLineToPoint(53 * scale, 52.5 * scale)
    hole.AddLineToPoint(47 * scale, 52.5 * scale)
    hole.CloseSubpath()
    gc.SetPen(wx.TRANSPARENT_PEN)
    gc.SetBrush(wx.Brush(_colour(spark if phase is None else ICE)))
    gc.FillPath(hole)


def draw(size, phase=None, locked=False):
    """The logo as a wx.Image with alpha, size pixels square.

    Small sizes leave out the fine detail so the mark stays crisp, and every
    size is drawn four times larger and scaled down for smooth edges.
    """
    size = max(8, int(size))
    big = size * 4
    image = wx.Image(big, big)
    image.InitAlpha()
    image.SetAlpha(bytes(big * big))
    gc = wx.GraphicsContext.Create(image)
    gc.SetAntialiasMode(wx.ANTIALIAS_DEFAULT)
    _paint(gc, big, phase, locked, detail=size >= 28)
    del gc  # finishes the drawing into the image
    return image.Scale(size, size, wx.IMAGE_QUALITY_HIGH)


def bitmap(size, phase=None, locked=False):
    return wx.Bitmap(draw(size, phase, locked))


def icon(size, phase=None, locked=False):
    result = wx.Icon()
    result.CopyFromBitmap(bitmap(size, phase, locked))
    return result


def icon_bundle():
    """Every size Windows asks for, for window title bars and the taskbar."""
    bundle = wx.IconBundle()
    for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
        bundle.AddIcon(icon(size))
    return bundle


def write_ico(path, sizes=(16, 20, 24, 32, 40, 48, 64, 128, 256)):
    """A Windows .ico holding one PNG per size."""
    import struct
    import tempfile

    images = []
    folder = tempfile.mkdtemp()
    for size in sizes:
        target = os.path.join(folder, f"{size}.png")
        draw(size).SaveFile(target, wx.BITMAP_TYPE_PNG)
        with open(target, "rb") as handle:
            images.append((size, handle.read()))
        os.remove(target)
    os.rmdir(folder)
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    table, blobs = b"", b""
    for size, data in images:
        table += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32,
                             len(data), offset + len(blobs))
        blobs += data
    with open(path, "wb") as handle:
        handle.write(header + table + blobs)


def export(folder):
    """Write the icon and the PNGs used by the build and the docs."""
    os.makedirs(folder, exist_ok=True)
    write_ico(os.path.join(folder, "zkeypass.ico"))
    draw(256).SaveFile(os.path.join(folder, "zkeypass-256.png"), wx.BITMAP_TYPE_PNG)
    draw(512).SaveFile(os.path.join(folder, "zkeypass-512.png"), wx.BITMAP_TYPE_PNG)
    strip = wx.Image(64 * 8, 64)
    strip.InitAlpha()
    strip.SetAlpha(bytes(64 * 8 * 64))
    for index in range(8):
        strip.Paste(draw(64, phase=index / 8.0), index * 64, 0)
    strip.SaveFile(os.path.join(folder, "zkeypass-animation-frames.png"),
                   wx.BITMAP_TYPE_PNG)


if __name__ == "__main__":
    _app = wx.App(False)
    _here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    export(os.path.join(_here, "assets"))
    print("written to", os.path.join(_here, "assets"))
