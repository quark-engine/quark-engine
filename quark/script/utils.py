# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
def getLength(argument: str) -> str:
    """Get the length of an argument.

    :param argument: string that holds the value of the argument
    :return: string that holds the length of the argument
    """

    indexOfDescriptor = argument.find("(")

    if indexOfDescriptor > 0:
        classAndMethodName = argument[:indexOfDescriptor]
    else:
        classAndMethodName = ""

    if classAndMethodName.endswith("length"):
        return argument
    else:
        return f"Ljava/lang/String;->length()I({argument})"
