# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
from quark.script.utils import getLength


def testGetLength():
    orignalValue = "v1"
    lengthOfValue = getLength(orignalValue)
    assert lengthOfValue == "Ljava/lang/String;->length()I(v1)"
