# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from ciphey import decrypt
from ciphey.iface import Config


def checkClearText(inputString: str) -> str:
    """Check the decrypted value of the input string.

    :param inputString: string to be checked.
    :return: the decrypted value
    """
    return decrypt(Config().library_default().complete_config(), inputString)
