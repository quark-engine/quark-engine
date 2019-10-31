class BytecodeObject:
    def __init__(self, mnemonic, registers, parameter):
        self._mnemonic = mnemonic
        self._registers = registers
        self._parameter = parameter

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def registers(self):
        return self._registers

    @property
    def parameter(self):
        return self._parameter
