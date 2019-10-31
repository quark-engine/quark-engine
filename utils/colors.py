from colorama import init
from colorama import Fore, Back, Style
import os
import sys


def COLOR_OUTPUT_RED(output):
    print(Fore.LIGHTRED_EX, output, Style.RESET_ALL, end="")


def COLOR_OUTPUT_GREEN(output):
    print(Fore.LIGHTGREEN_EX, output, Style.RESET_ALL, end="")


def COLOR_OUTPUT_YELLOW(output):
    print(Fore.LIGHTYELLOW_EX, output, Style.RESET_ALL, end="")


def COLOR_OUTPUT_CYAN(output):
    print(Fore.LIGHTCYAN_EX, output, Style.RESET_ALL)


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
    return color(text, 31)


def green(text):
    return color(text, 32)


def yel(text):
    return color(text, 33)


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
