# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import base64
import ipaddress
import re

IP_ADDRESS_REGEX = r"(?:\d{1,3}\.)+(?:\d{1,3})"

URL_REGEX = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

VALIDATE_URL = (
    r"^(?:http|ftp)s?://"  # http:// or https://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
    r"localhost|"  # localhost...
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
    r"(?::\d+)?"  # optional port
    r"(?:/?|[/?]\S+)$"
)

ANDROID_CONTENT = "content://"
ANDROID_FILE = "file://"


def validate_url(url):
    regex = re.compile(VALIDATE_URL, re.IGNORECASE)

    return re.match(regex, url) is not None


def validate_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


def validate_base64(sb):
    try:
        if isinstance(sb, str):
            # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, "ascii")
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def extract_ip(string):
    ip = re.findall(IP_ADDRESS_REGEX, string)
    return [x for x in ip if validate_ip_address(x)]


def extract_url(string):
    url = re.findall(URL_REGEX, string)

    return [x[0] for x in url if validate_url(x[0])]


def extract_content(string):
    if ANDROID_CONTENT in string:
        return string
    return None


def extract_file(string):
    if ANDROID_FILE in string:
        return string
    return None
