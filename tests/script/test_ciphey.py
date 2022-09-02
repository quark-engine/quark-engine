# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from quark.script.ciphey import checkClearText


def testCheckClearTextWithClearText():
    assert checkClearText("Clear Text") == "Clear Text"


def testCheckClearTextWithCipherText():
    assert (
        checkClearText("NB2HI4DTHIXS6Z3PN5TWYZJOMNXW2===")
        == "https://google.com"
    )
