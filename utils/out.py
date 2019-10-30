from prettytable import PrettyTable
from .colors import *


def print_info(message):
    print(bold(cyan("[*]")) + " {0}".format(message))


def print_warning(message):
    print(bold(yellow("[!]")) + " WARNING: {0}".format(message))


def print_error(message):
    print(bold(red("[!]")) + " ERROR: {0}".format(message))


def print_success(message):
    print(bold(green("[+]")) + " DONE: {0}".format(message))


def table(header, rows):
    table = PrettyTable(header)
    table.align = "l"
    table.padding_width = 1

    for row in rows:
        table.add_row(row)

    return table
