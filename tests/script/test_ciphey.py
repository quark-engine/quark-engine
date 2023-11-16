# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import sys
import importlib
from unittest import TestCase
from quark.script.ciphey import checkClearText


class TestWithoutCiphey(TestCase):
    def setUp(self):
        self._tmpCipheyModule = sys.modules["ciphey"]
        sys.modules["ciphey"] = None
        importlib.reload(sys.modules["quark.script.ciphey"])

    def tearDown(self):
        sys.modules["ciphey"] = self._tmpCipheyModule
        importlib.reload(sys.modules["quark.script.ciphey"])

    def testCheckClearTextWithCipheyImportError(self):
        assert checkClearText("Clear Text") is None


def testCheckClearTextWithClearText():
    assert checkClearText("Clear Text") == "Clear Text"


def testCheckClearTextWithCipherText():
    assert (
        checkClearText("NB2HI4DTHIXS6Z3PN5TWYZJOMNXW2===")
        == "https://google.com"
    )
