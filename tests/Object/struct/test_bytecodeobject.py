import pytest
from quark.core.struct.bytecodeobject import BytecodeObject


@pytest.fixture()
def bytecode_obj():
    bytecode_obj = BytecodeObject(
        "invoke-direct",
        "v1",
        "java.io.FilterOutputStream.close:()V",
    )

    yield bytecode_obj

    del bytecode_obj


class TestBytecodeObject:
    def test_init(self, bytecode_obj):
        with pytest.raises(TypeError):
            bytecode_obj_with_no_argu = BytecodeObject()

        assert isinstance(bytecode_obj, BytecodeObject)

        assert bytecode_obj.mnemonic == "invoke-direct"

        assert bytecode_obj.registers == "v1"

        assert bytecode_obj.parameter == "java.io.FilterOutputStream.close:()V"
