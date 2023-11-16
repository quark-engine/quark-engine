# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

try:
    from ciphey import decrypt
    from ciphey.iface import Config

    isCipheyImported = True
except ImportError:
    isCipheyImported = False


def checkClearText(inputString: str) -> str:
    """Check the decrypted value of the input string.

    :param inputString: string to be checked.
    :return: the decrypted value
    """
    if isCipheyImported:
        return decrypt(
            Config().library_default().complete_config(), inputString
        )

    return None
