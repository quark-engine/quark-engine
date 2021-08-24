import pytest

from quark.utils.regex import (
    extract_content,
    extract_file,
    extract_ip,
    extract_url,
    validate_base64,
    validate_ip_address,
    validate_url,
)


@pytest.fixture(
    scope="module",
    params=[
        "http://doc.quark-engine.com",  # Domain
        "ftp://127.0.0.1",  # Ip address
        "https://localhost",  # localhost
        "http://domain:8888",  # port
        "http://domain/file",  # path
        "http://domain?query=val",  # query
        "http://domain:8888/path/file?query=val",  # compound
    ],
)
def valid_url(request):
    return request.param


@pytest.fixture(
    scope="module",
    params=[
        "http",
        "127.0.0.1",
        "localhost",
        "127.0.0.1:8888",
        "path/file",
        "var=val",
    ],
)
def invalid_url(request):
    return request.param


@pytest.fixture(scope="module")
def valid_ip():
    return "127.0.0.1"


@pytest.fixture(scope="module", params=["127.0.0", "127.0.0.1.0"])
def invalid_ip(request):
    return request.param


@pytest.mark.xfail(reason="Requirement for the future")
def test_validate_url_with_valid_string(valid_url):
    result = validate_url(valid_url)

    assert result is True


def test_validate_url_with_invalid_string(invalid_url):
    result = validate_url(invalid_url)

    assert result is False


def test_validate_ip_address_with_valid_string(valid_ip):
    result = validate_ip_address(valid_ip)

    assert result is True


def test_validate_ip_address_with_invalid_string(invalid_ip):
    result = validate_ip_address(invalid_ip)

    assert result is False


def test_validate_base64_with_valid_string():
    result = validate_base64("TWVzc2VuZ2U=")

    assert result is True


def test_validate_base64_with_invalid_string():
    result = validate_base64("NOT_A_BASE64")

    assert result is False


def test_extract_ip_with_no_result():
    result = extract_ip("CXS127.0.O.1DIO8.8.8.BDC")

    assert result == []


def test_extract_ip_with_result():
    result = extract_ip("CXS127.0.0.1DIO8.8.8.8DC")

    assert result == ["127.0.0.1", "8.8.8.8"]


def test_extract_url_with_no_result():
    url = "HTTPS://127.0.O.1.0/?DFCHTTPS:/VAL?/?REIOS1"

    result = extract_url(url)

    assert result == []


def test_extract_url_with_result():
    url = "CHAR https://www.google.com/search?q=QUARK CHAR"

    result = extract_url(url)

    assert result == ["https://www.google.com/search?q=QUARK"]


def test_extract_content_with_no_result():
    url = "NOT_A_CONTENT"

    result = extract_content(url)

    assert result is None


def test_extract_content_with_result():
    url = "CHARcontent://SMS/SENTCHAR"

    result = extract_content(url)

    assert result == url


def test_extract_file_with_no_result():
    url = "NOT_A_FILE"

    result = extract_file(url)

    assert result is None


def test_extract_content_with_result():
    url = "CHARfile://usr/bin/shCHAR"

    result = extract_file(url)

    assert result == url
