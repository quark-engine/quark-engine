# -*- coding: utf-8 -*-
# This file is part of Quark-Engine:
# https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import subprocess
import re


def checkClearText(inputString: str) -> str:
    """Check the decrypted value of the input string.

    :param inputString: string to be checked.
    :raises ImportError: if Ares is not installed
    :return: the decrypted value
    """
    try:
        if inputString is None:
            return None

        command = ["ares", "-dt", inputString]
        aresOutput = subprocess.run(
            command, capture_output=True, text=True, check=True
        )
        patternToEscapeANSIColorCode = re.compile(
            r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
        )
        matchClearText = re.search(
            r"The plaintext is:\s*(.+)",
            patternToEscapeANSIColorCode.sub("", aresOutput.stdout),
        )

        if matchClearText:
            return matchClearText.group(1).strip()

    except FileNotFoundError as exception:
        raise Exception(
            "Ares is not installed. Please follow"
            " the instruction on the github page"
            " 'https://github.com/bee-san/Ares'"
            " and use cargo to install the tool."
        ) from exception
