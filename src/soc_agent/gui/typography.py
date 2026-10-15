"""System Pango/Cairo text in Tk images when bundled Tk lacks scalable Xft fonts.

No GTK window, subprocess, installation, font download or global Tk configuration.
All PhotoImage creation and destruction belongs to the Tk creator thread.
"""

import base64
import ctypes as c
import ctypes.util
import threading
import tkinter as tk
from collections import OrderedDict


class Typography:
    def __init__(self, root):
        self.root, self.owner = root, threading.get_ident()
        self.cache = OrderedDict()
        libs = {}
        for name in ("cairo", "pango-1.0", "pangocairo-1.0", "gobject-2.0"):
            path = ctypes.util.find_library(name)
            if not path:
                raise OSError("SCALABLE_SYSTEM_TEXT_UNAVAILABLE")
            libs[name] = c.CDLL(path)

        def bind(lib, name, result, args):
            value = getattr(libs[lib], name)
            value.restype, value.argtypes = result, args
            setattr(self, name, value)

        ptr, integer, double = c.c_void_p, c.c_int, c.c_double
        for name, result, args in (
            ("cairo_image_surface_create", ptr, [integer, integer, integer]),
            ("cairo_create", ptr, [ptr]),
            ("cairo_destroy", None, [ptr]),
            ("cairo_surface_destroy", None, [ptr]),
            ("cairo_set_source_rgb", None, [ptr, double, double, double]),
            ("cairo_font_options_create", ptr, []),
            ("cairo_font_options_set_antialias", None, [ptr, integer]),
            ("cairo_set_font_options", None, [ptr, ptr]),
            ("cairo_font_options_destroy", None, [ptr]),
        ):
            bind("cairo", name, result, args)
        self.writer_type = c.CFUNCTYPE(integer, ptr, c.POINTER(c.c_ubyte), c.c_uint)
        bind("cairo", "cairo_surface_write_to_png_stream", integer, [ptr, self.writer_type, ptr])
        bind("pangocairo-1.0", "pango_cairo_create_layout", ptr, [ptr])
        bind("pangocairo-1.0", "pango_cairo_show_layout", None, [ptr, ptr])
        for name, result, args in (
            ("pango_font_description_from_string", ptr, [c.c_char_p]),
            ("pango_font_description_set_absolute_size", None, [ptr, double]),
            ("pango_font_description_free", None, [ptr]),
            ("pango_layout_set_font_description", None, [ptr, ptr]),
            ("pango_layout_set_text", None, [ptr, c.c_char_p, integer]),
            ("pango_layout_set_width", None, [ptr, integer]),
            ("pango_layout_set_ellipsize", None, [ptr, integer]),
            ("pango_layout_get_pixel_size", None, [ptr, c.POINTER(integer), c.POINTER(integer)]),
            ("pango_layout_get_unknown_glyphs_count", integer, [ptr]),
        ):
            bind("pango-1.0", name, result, args)
        bind("gobject-2.0", "g_object_unref", None, [ptr])
        self.last_unknown_glyphs = 0

    def photo(self, text, size=14, color="#F1F5F9", bold=False, width=1400):
        if threading.get_ident() != self.owner:
            raise RuntimeError("TK_TEXT_THREAD_BOUNDARY")
        text = str(text)[:4000]
        if not 9 <= size <= 48 or not 24 <= width <= 2200:
            raise ValueError("TEXT_RENDER_LIMIT")
        key = (text, size, color, bold, width)
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        surface = self.cairo_image_surface_create(0, width + 4, size * 4)
        context = self.cairo_create(surface)
        options = self.cairo_font_options_create()
        self.cairo_font_options_set_antialias(options, 2)
        self.cairo_set_font_options(context, options)
        layout = self.pango_cairo_create_layout(context)
        font = self.pango_font_description_from_string(
            b"DejaVu Sans Bold" if bold else b"DejaVu Sans"
        )
        try:
            self.pango_font_description_set_absolute_size(font, size * 1024)
            self.pango_layout_set_font_description(layout, font)
            self.pango_layout_set_width(layout, width * 1024)
            self.pango_layout_set_ellipsize(layout, 3)
            self.pango_layout_set_text(layout, text.encode("utf-8"), -1)
            self.last_unknown_glyphs = self.pango_layout_get_unknown_glyphs_count(layout)
            w, h = c.c_int(), c.c_int()
            self.pango_layout_get_pixel_size(layout, c.byref(w), c.byref(h))
            rgb = tuple(int(color[i : i + 2], 16) / 255 for i in (1, 3, 5))
            self.cairo_set_source_rgb(context, *rgb)
            self.pango_cairo_show_layout(context, layout)
            chunks = []

            @self.writer_type
            def write(_closure, data, length):
                chunks.append(c.string_at(data, length))
                return 0

            if self.cairo_surface_write_to_png_stream(surface, write, None):
                raise OSError("TEXT_RENDER_FAILED")
            image = tk.PhotoImage(master=self.root, data=base64.b64encode(b"".join(chunks)))
            cropped = tk.PhotoImage(master=self.root, width=max(1, w.value), height=max(1, h.value))
            self.root.tk.call(
                cropped, "copy", image, "-from", 0, 0, max(1, w.value), max(1, h.value)
            )
            self.cache[key] = cropped
            if len(self.cache) > 192:
                self.cache.popitem(last=False)
            return cropped
        finally:
            self.pango_font_description_free(font)
            self.g_object_unref(layout)
            self.cairo_font_options_destroy(options)
            self.cairo_destroy(context)
            self.cairo_surface_destroy(surface)


def typography(widget):
    root = widget.winfo_toplevel()
    if not hasattr(root, "soc_typography"):
        root.soc_typography = Typography(root)
    return root.soc_typography


class Label(tk.Label):
    def __init__(
        self,
        parent,
        *,
        text="",
        size=14,
        fg="#F1F5F9",
        bg="#0B1220",
        bold=False,
        textvariable=None,
        max_width=1200,
        **kwargs,
    ):
        self.render_size, self.render_color, self.render_bold = size, fg, bold
        self.max_width, self.variable, self.trace = max_width, textvariable, None
        super().__init__(parent, text=text, bg=bg, anchor="w", borderwidth=0, **kwargs)
        if textvariable is not None:
            self.trace = textvariable.trace_add(
                "write", lambda *_: self._render(textvariable.get())
            )
            text = textvariable.get()
        self._render(text)

    def _render(self, text):
        size = 17 if str(text) == "UNKNOWN" and self.render_size >= 28 else self.render_size
        self.image = typography(self).photo(
            text, size, self.render_color, self.render_bold, self.max_width
        )
        super().configure(image=self.image, text=text)

    def configure(self, cnf=None, **kwargs):
        text = kwargs.pop("text", None)
        if "fg" in kwargs:
            self.render_color = kwargs.pop("fg")
        result = super().configure(cnf, **kwargs)
        self._render(self.cget("text") if text is None else text)
        return result

    def destroy(self):
        if self.trace is not None:
            self.variable.trace_remove("write", self.trace)
        super().destroy()


def text(canvas, x, y, value, *, size=13, fill="#94A3B8", anchor="w", width=1000, bold=False, **kw):
    image = typography(canvas).photo(value, size, fill, bold, width)
    canvas.text_images.append(image)
    return canvas.create_image(x, y, image=image, anchor=anchor, **kw)
