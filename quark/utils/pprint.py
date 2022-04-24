# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from prettytable import PrettyTable
from quark.utils.colors import bold, cyan, green, red, yellow


def clear_the_last_line():
    """
    Clear the last line of the terminal.
    """
    print("\033[A\033[A")


def print_info(message):
    print(bold(cyan("[*]")) + f" {message}")


def print_warning(message):
    print(bold(yellow("[!]")) + f" WARNING: {message}")


def print_error(message):
    print(bold(red("[!]")) + f" ERROR: {message}")


def print_success(message):
    print(bold(green("[+]")) + f" DONE: {message}")


def table(header, rows):
    tb = PrettyTable(header)
    tb.align = "l"
    tb.padding_width = 1

    for row in rows:
        tb.add_row(row)

    return tb
