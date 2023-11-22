# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.


def checkClearText(inputString: str) -> str:
    """Check if the input string is in clear text with Ciphey.
    If Ciphey is not installed, raise ImportError.
    
    :param inputString: string to be checked.
    :return: the decrypted value
    """
    try:
        from ciphey import decrypt
        from ciphey.iface import Config

    except ImportError as exception:
        raise ImportError(
            "Ciphey is not installed. Please use the command"
            " 'python3 -m pip install ciphey --upgrade'"
            " to install the package."
        ) from exception

    return decrypt(Config().library_default().complete_config(), inputString)
