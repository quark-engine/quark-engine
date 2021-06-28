import os
import sys

from quark.utils.colors import color


def test_color():
    text = "Text"
    color_code = 1

    colored_text = color(text, color_code)

    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        assert colored_text == text
    else:
        assert colored_text == "\x1b[1mText\x1b[0m"
