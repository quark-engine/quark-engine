class DecompilerDAD:
    def __init__(self, vm, vmx):
        """
        Decompiler wrapper for DAD: **D**AD is **A** **D**ecompiler
        DAD is the androguard internal decompiler.

        This Method does not use the :class:`~androguard.decompiler.dad.decompile.DvMachine` but
        creates :class:`~androguard.decompiler.dad.decompile.DvClass` and
        :class:`~androguard.decompiler.dad.decompile.DvMethod` on demand.

        :param androguard.core.bytecodes.dvm.DalvikVMFormat vm: `DalvikVMFormat` object
        :param androguard.core.analysis.analysis.Analysis vmx: `Analysis` object
        """
        self.vm = vm
        self.vmx = vmx


