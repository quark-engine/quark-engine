# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
from unittest import TestCase
from unittest.mock import patch
from quark.script.ciphey import checkClearText


class TestCiphey(TestCase):
    @patch(
        "builtins.__import__",
        side_effect=ImportError("No module named 'ciphey'"),
    )
    def testCheckClearTextWithCipheyImportError(self, mock_import):
        with self.assertRaises(Exception) as context:
            checkClearText("Clear Text")
        assert "Ciphey is not installed." in str(context.exception)

    def testCheckClearTextWithClearText(self):
        assert checkClearText("Clear Text") == "Clear Text"

    def testCheckClearTextWithCipherText(self):
        assert (
            checkClearText("NB2HI4DTHIXS6Z3PN5TWYZJOMNXW2===")
            == "https://google.com"
        )
