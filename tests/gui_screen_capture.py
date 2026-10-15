"""Capture an actual mapped Tk X11 window. PNG encoding only, no generated/mock UI."""

import ctypes as c
import ctypes.util
import struct
import zlib
from pathlib import Path


class XImage(c.Structure):
    _fields_ = [
        ("width", c.c_int),
        ("height", c.c_int),
        ("xoffset", c.c_int),
        ("format", c.c_int),
        ("data", c.c_void_p),
        ("byte_order", c.c_int),
        ("bitmap_unit", c.c_int),
        ("bitmap_bit_order", c.c_int),
        ("bitmap_pad", c.c_int),
        ("depth", c.c_int),
        ("bytes_per_line", c.c_int),
        ("bits_per_pixel", c.c_int),
        ("red_mask", c.c_ulong),
        ("green_mask", c.c_ulong),
        ("blue_mask", c.c_ulong),
    ]


def capture(root, path: Path):
    root.update_idletasks()
    root.update()
    lib = c.CDLL(ctypes.util.find_library("X11"))
    lib.XOpenDisplay.argtypes = [c.c_char_p]
    lib.XOpenDisplay.restype = c.c_void_p
    lib.XGetImage.argtypes = [
        c.c_void_p,
        c.c_ulong,
        c.c_int,
        c.c_int,
        c.c_uint,
        c.c_uint,
        c.c_ulong,
        c.c_int,
    ]
    lib.XGetImage.restype = c.POINTER(XImage)
    lib.XDestroyImage.argtypes = [c.POINTER(XImage)]
    lib.XCloseDisplay.argtypes = [c.c_void_p]
    display = lib.XOpenDisplay(None)
    if not display:
        raise RuntimeError("X11_DISPLAY_UNAVAILABLE")
    width, height = root.winfo_width(), root.winfo_height()
    image = lib.XGetImage(display, root.winfo_id(), 0, 0, width, height, c.c_ulong(-1), 2)
    if not image:
        raise RuntimeError("MAPPED_WINDOW_CAPTURE_FAILED")
    try:
        value = image.contents
        if (
            value.bits_per_pixel,
            value.byte_order,
            value.red_mask,
            value.green_mask,
            value.blue_mask,
        ) != (32, 0, 0xFF0000, 0xFF00, 0xFF):
            raise RuntimeError("UNSUPPORTED_CAPTURE_PIXEL_LAYOUT")
        raw = c.string_at(value.data, value.bytes_per_line * height)
        pixels = bytearray()
        for row in range(height):
            pixels.append(0)
            start = row * value.bytes_per_line
            for offset in range(start, start + width * 4, 4):
                pixels.extend(raw[offset : offset + 3][::-1])

        def chunk(name, data):
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
            )

        output = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(pixels)))
            + chunk(b"IEND", b"")
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(output)
    finally:
        lib.XDestroyImage(image)
        lib.XCloseDisplay(display)
