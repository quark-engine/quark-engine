# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
from quark.script.utils import isTrue


def testIsTrue():
    argument = "1"
    assert isTrue(argument)
