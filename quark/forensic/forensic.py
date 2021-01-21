# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from quark.Objects.apkinfo import Apkinfo
from quark.utils.regex import (
    extract_url,
    extract_ip,
    extract_content,
    validate_base64,
    extract_file,
)


class Forensic:
    __slots__ = ["apk", "all_strings"]

    def __init__(self, apkpath):
        self.apk = Apkinfo(apkpath)
        self.all_strings = self.apk.get_strings()

    def get_all_strings(self):
        """
        Return all the strings inside the APK with a set.
        """
        return self.all_strings

    def get_url(self):
        """
        Return all the url strings inside the APK with a set.
        """

        url = set()

        for string in self.all_strings:

            if extract_url(string):
                for url_string in extract_url(string):
                    url.add(url_string)

        return url

    def get_ip(self):
        """
        Return all the ip address strings inside the APK with a set.
        """

        ip = set()

        for string in self.all_strings:

            if extract_ip(string):

                for ip_string in extract_ip(string):
                    ip.add(ip_string)

        return ip

    def get_content(self):
        """
        Return all the content strings inside the APK with a set.
        """
        content = set()

        for string in self.all_strings:

            if extract_content(string):
                content.add(string)

        return content

    def get_file(self):
        """
        Return all the content strings inside the APK with a set.
        """
        file = set()

        for string in self.all_strings:

            if extract_file(string):
                file.add(string)

        return file

    def get_base64(self):

        base64 = set()

        for string in self.all_strings:

            if validate_base64(string):
                base64.add(string)

        return base64


if __name__ == "__main__":
    # Usage

    # fc = Forensic("../sample/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk")
    # fc = Forensic("../sample/14d9f1a92dd984d6040cc41ed06e273e.apk")
    # fc = Forensic("../sample/HippoSMS.apk")
    fc = Forensic("../sample/obfuscation/com.cdim.driver.core.apk")

    print("URL Found")
    for i in fc.get_url():
        print(i)

    print("IP Found")
    for i in fc.get_ip():
        print(i)

    print("Content Found")
    for i in fc.get_content():
        print(i)

    print("FILE Found")
    for i in fc.get_file():
        print(i)

    print("Base64 Found")
    for i in fc.get_base64():
        print(i)
