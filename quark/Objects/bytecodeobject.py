# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.
"""BytecodeObject is used to store the instructions in smali, including mnemonic, registers, parameter"""


class BytecodeObject:
    """BytecodeObject is used to store the instructions in smali, including mnemonic, registers, parameter"""

    def __init__(self, mnemonic, registers, parameter):
        """
        ['invoke-virtual', 'v3', 'Lcom/google/progress/APNOperator;->deleteAPN()Z']

        :param mnemonic:
        :param registers:
        :param parameter:
        """
        self._mnemonic = mnemonic
        self._registers = registers
        self._parameter = parameter

    def __repr__(self):
        return f"<BytecodeObject-mnemonic:{self._mnemonic}, registers:{self._registers}, parameter:{self._parameter}>"

    @property
    def mnemonic(self):
        """
        Dalvik bytecode instructions set, for example 'invoke-virtual'.

        :return: a string of mnemonic
        """
        return self._mnemonic

    @property
    def registers(self):
        """
        Registers used in Dalvik instructions, for example '[v3]'.

        :return: a list containing all the registers used
        """
        return self._registers

    @property
    def parameter(self):
        """
        Commonly used for functions called by invoke-kind instructions, for example
        'Lcom/google/progress/APNOperator;->deleteAPN()Z'.

        :return: a string of the function name
        """
        return self._parameter