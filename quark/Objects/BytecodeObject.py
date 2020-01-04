class BytecodeObject:
    def __init__(self, mnemonic, registers, parameter):
        self._mnemonic = mnemonic
        self._registers = registers
        self._parameter = parameter

    def __repr__(self):
        return "<BytecodeObject-mnemonic:{}, registers:{}, parameter:{}>".format(self._mnemonic, self._registers,
                                                                                 self._parameter)

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def registers(self):
        return self._registers

    @property
    def parameter(self):
        return self._parameter
