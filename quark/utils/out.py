from prettytable import PrettyTable
from quark.utils.colors import bold, cyan, yellow, red, green


def print_info(message):
    print(bold(cyan("[*]")) + " {0}".format(message))


def print_warning(message):
    print(bold(yellow("[!]")) + " WARNING: {0}".format(message))


def print_error(message):
    print(bold(red("[!]")) + " ERROR: {0}".format(message))


def print_success(message):
    print(bold(green("[+]")) + " DONE: {0}".format(message))


def table(header, rows):
    tb = PrettyTable(header)
    tb.align = "l"
    tb.padding_width = 1

    for row in rows:
        tb.add_row(row)

    return tb
