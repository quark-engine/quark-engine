import base64
import sys

import pytest
from quark.utils.pprint import (
    print_error,
    print_info,
    print_success,
    print_warning,
    table,
)


@pytest.fixture(scope="module")
def bold_style():
    return "\x1b[1m"


@pytest.fixture(scope="module")
def cyan_color():
    return "\x1b[36m"


@pytest.fixture(scope="module")
def yellow_color():
    return "\x1b[33m"


@pytest.fixture(scope="module")
def red_color():
    return "\x1b[91m"


@pytest.fixture(scope="module")
def green_color():
    return "\x1b[92m"


def test_print_info(capsys, bold_style, cyan_color):
    message = "message"

    print_info(message)

    output = capsys.readouterr().out
    if not sys.platform.startswith("win32"):
        assert bold_style in output
        assert cyan_color in output

    assert message in output


def test_print_warning(capsys, bold_style, yellow_color):
    message = "message"

    print_warning(message)

    output = capsys.readouterr().out
    if not sys.platform.startswith("win32"):
        assert bold_style in output
        assert yellow_color in output

    assert "WARNING" in output
    assert message in output


def test_print_error(capsys, bold_style, red_color):
    message = "message"

    print_error(message)

    output = capsys.readouterr().out
    if not sys.platform.startswith("win32"):
        assert bold_style in output
        assert red_color in output

    assert "ERROR" in output
    assert message in output


def test_print_success(capsys, bold_style, green_color):
    message = "message"

    print_success(message)

    output = capsys.readouterr().out
    if not sys.platform.startswith("win32"):
        assert bold_style in output
        assert green_color in output

    assert "DONE" in output
    assert message in output


def test_table():
    expected_csv = base64.b64decode(
        "Q29sdW1uIDEsQ29sdW1uIDIsQ29sdW1uIDMNClJv" "dyAxLDExLDIyDQpSb3cgMiwzMyw0NA0K"
    ).decode()

    header = ["Column 1", "Column 2", "Column 3"]
    rows = [["Row 1", "11", "22"], ["Row 2", "33", "44"]]

    table_obj = table(header, rows)

    assert table_obj.get_csv_string() == expected_csv
