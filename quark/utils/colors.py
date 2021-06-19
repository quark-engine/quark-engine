# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
import sys

CHECK_LIST = "".join(["\t[" + "\u2713" + "]"])


def color(text, color_code):
    """Colorize text.
    @param text: text.
    @param color_code: color.
    @return: colorized text.
    """
    # $TERM under Windows:
    # cmd.exe -> "" (what would you expect..?)
    # cygwin -> "cygwin" (should support colors, but doesn't work somehow)
    # mintty -> "xterm" (supports colors)
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    return "\x1b[%dm%s\x1b[0m" % (color_code, text)


def black(text):
    return color(text, 30)


def yellow(text):
    return color(text, 33)


def red(text):
    return color(text, 91)


def green(text):
    return color(text, 92)


def blue(text):
    return color(text, 34)


def magenta(text):
    return color(text, 35)


def cyan(text):
    return color(text, 36)


def white(text):
    return color(text, 37)


def bold(text):
    return color(text, 1)


def lightyellow(text):
    return color(text, 93)


def lightblue(text):
    return color(text, 94)


def colorful_report(arg0):
    print(red(CHECK_LIST), end="")
    print(green(bold(arg0)), end="")
    print("")
