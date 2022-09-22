# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
def isArgumentTrue(argument: str) -> bool:
    """Check if the argument holds the Boolean value, True.

    :param argument: string that holds the value of a register
    :return: True/False
    """
    return argument == "1"
