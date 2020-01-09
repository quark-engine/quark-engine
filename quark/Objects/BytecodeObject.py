class BytecodeObject:
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
        return "<BytecodeObject-mnemonic:{}, registers:{}, parameter:{}>".format(self._mnemonic, self._registers,
                                                                                 self._parameter)

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
