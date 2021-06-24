import pytest
from unittest.mock import patch

from quark.Evaluator.pyeval import PyEval, MAX_REG_COUNT
from quark.Objects.tableobject import TableObject
from quark.Objects.registerobject import RegisterObject


@pytest.fixture()
def instructions():
    ins = [
        "invoke-virtual",
        "invoke-direct",
        "move-result-object",
        "new-instance",
        "const-string",
        "const/4",
        "aget-object",
    ]

    yield ins

    del ins


@pytest.fixture()
def pyeval():
    pyeval = PyEval()

    # mock_hash_table = [...[], [v4_mock_variable_obj], [], [],
    # [v9_mock_variable_obj]....]
    v4_mock_variable_obj = RegisterObject(
        "v4",
        "Lcom/google/progress/SMSHelper;",
        None,
    )
    v9_mock_variable_obj = RegisterObject(
        "v9",
        "some_string",
        "java.io.file.close()",
    )
    pyeval.table_obj.insert(4, v4_mock_variable_obj)
    pyeval.table_obj.insert(9, v9_mock_variable_obj)

    yield pyeval

    del pyeval


class TestPyEval:
    def test_init(self):
        pyeval = PyEval()

        assert len(pyeval.table_obj.hash_table) == MAX_REG_COUNT
        assert isinstance(pyeval.table_obj, TableObject)
        assert pyeval.ret_stack == []

    # Tests for _invoke
    def test_invoke_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(IndexError):
            pyeval._invoke(instruction)

    def test_invoke_with_wrong_types(self, pyeval):
        instruction = [1, 2, 3]

        with pytest.raises(TypeError):
            pyeval._invoke(instruction)

    def test_invoke_with_invalid_value(self, pyeval):
        instruction = ["invoke-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._invoke(instruction)

    def test_invoke_with_func_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()Lclass;"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(4).called_by_func == [
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()",
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.ret_stack == [
            "some_function()Lclass;(Lcom/google/progress/SMSHelper;,some_string)"
        ]

    @pytest.mark.skip(reason="discussion needed.")
    def test_invoke_with_func_not_returning_value(self, pyeval):
        instruction = ["invoke-kind", "v4", "v9", "some_function()V"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(4).called_by_func == [
            "some_function()V(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()",
            "some_function()V(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.ret_stack == []

    def test_invoke_without_registers(self, pyeval):
        instruction = ["invoke-static", "some-func()Lclass;"]

        pyeval._invoke(instruction)

        assert pyeval.table_obj.pop(9).called_by_func == ["java.io.file.close()"]
        assert pyeval.ret_stack == ["some-func()Lclass;()"]

    # Tests for invoke_virtual
    def test_invoke_virtual_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-virtual", "v4", "v9", "some_function()V"]

        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_VIRTUAL(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke_direct
    def test_invoke_direct_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-direct", "v4", "v9", "some_function()V"]

        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_DIRECT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke_static
    def test_invoke_static_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-static", "v4", "v9", "some_function()V"]

        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_STATIC(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke-interface
    def test_invoke_interface_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-interface", "v4", "v9", "some_function()V"]

        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_INTERFACE(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for _move
    def test_move_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._move(instruction)

    def test_move_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(IndexError):
            pyeval._move(instruction)

    def test_move_with_invalid_instrcution(self, pyeval):
        instruction = ["move-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._move(instruction)

    def test_move_with_valid_instrcution(self, pyeval):
        instruction = ["move-result-object", "v1"]
        expected_return_value = "some_function()V(used_register_1, used_register_2)"
        pyeval.ret_stack.append(expected_return_value)

        pyeval._move(instruction)

        assert pyeval.table_obj.pop(1).value == expected_return_value
        assert pyeval.table_obj.pop(1).called_by_func == []

    # Tests for move_result
    def test_move_result_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result", "v1"]

        with patch("quark.Evaluator.pyeval.PyEval._move") as mock:
            pyeval.MOVE_RESULT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for move_result_wide
    def test_move_result_wide_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result-wide", "v1"]
        return_value = "Return Value"
        pyeval.ret_stack.append("Return Value")

        pyeval.MOVE_RESULT_WIDE(instruction)

        assert pyeval.table_obj.pop(1).value == return_value
        assert pyeval.table_obj.pop(2).value == return_value

    # Tests for move_result_object
    def test_move_result_object_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result-object", "v1"]

        with patch("quark.Evaluator.pyeval.PyEval._move") as mock:
            pyeval.MOVE_RESULT_OBJECT(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for new instance
    def test_new_instance(self, pyeval):
        instruction = ["new-instance", "v3", "Lcom/google/progress/SMSHelper;"]

        override_original_instruction = [
            "new-instance",
            "v4",
            "override_value",
        ]

        pyeval.NEW_INSTANCE(instruction)

        assert pyeval.table_obj.pop(3).register_name == "v3"
        assert (
            pyeval.table_obj.pop(
                3,
            ).value
            == "Lcom/google/progress/SMSHelper;"
        )
        assert pyeval.table_obj.pop(3).called_by_func == []

        assert pyeval.table_obj.pop(4).register_name == "v4"
        assert (
            pyeval.table_obj.pop(
                4,
            ).value
            == "Lcom/google/progress/SMSHelper;"
        )
        assert pyeval.table_obj.pop(4).called_by_func == []

        pyeval.NEW_INSTANCE(override_original_instruction)

        assert pyeval.table_obj.pop(4).register_name == "v4"
        assert pyeval.table_obj.pop(4).value == "override_value"
        assert pyeval.table_obj.pop(4).called_by_func == []

    # Tests for const_string
    def test_const_string(self, pyeval):
        instruction = [
            "const-string",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.CONST_STRING(instruction)

        assert pyeval.table_obj.pop(8).register_name == "v8"
        assert (
            pyeval.table_obj.pop(8).value
            == "https://github.com/quark-engine/quark-engine"
        )
        assert pyeval.table_obj.pop(8).called_by_func == []

    # Tests for const
    def test_const(self, pyeval):
        instruction = ["const", "v1", "string value"]

        with patch("quark.Evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-four
    def test_const_four(self, pyeval):
        instruction = [
            "const/4",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        with patch("quark.Evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_FOUR(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-sixteen
    def test_const_sixteen(self, pyeval):
        instruction = ["const/16", "v1", "123"]

        with patch("quark.Evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_SIXTEEN(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for const-high-sixteen
    def test_const_high_sixteen(self, pyeval):
        instruction = ["const/high16", "v1", "123"]

        with patch("quark.Evaluator.pyeval.PyEval._assign_value") as mock:
            pyeval.CONST_HIGHSIXTEEN(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for aget-object
    def test_aget_object(self, pyeval):
        """
        aget-object vx,vy,vz

        It means vx = vy[vz].
        """
        v2_mock_variable_obj = RegisterObject(
            "v2",
            "some_list_like[1,2,3,4]",
            "java.io.file.close()",
        )
        v3_mock_variable_obj = RegisterObject("v3", "2", None)
        pyeval.table_obj.insert(2, v2_mock_variable_obj)
        pyeval.table_obj.insert(3, v3_mock_variable_obj)

        instruction = ["aget-object", "v1", "v2", "v3"]

        pyeval.AGET_OBJECT(instruction)

        pyeval.table_obj.pop(1).register_name == "v1"
        pyeval.table_obj.pop(1).value = "some_list_like[1,2,3,4][2]"
        assert pyeval.table_obj.pop(1).called_by_func == []

    def test_show_table(self, pyeval):
        assert len(pyeval.show_table()[4]) == 1
        assert len(pyeval.show_table()[9]) == 1
        assert len(pyeval.show_table()[3]) == 0

        assert isinstance(pyeval.show_table()[4][0], RegisterObject)
        assert isinstance(pyeval.show_table()[9][0], RegisterObject)

    def test_invoke_and_move(self, pyeval):
        v6_mock_variable_obj = RegisterObject("v6", "some_string", None)

        pyeval.table_obj.insert(6, v6_mock_variable_obj)

        assert pyeval.table_obj.pop(6).register_name == "v6"
        assert pyeval.table_obj.pop(6).value == "some_string"
        assert pyeval.table_obj.pop(6).called_by_func == []

        first_instruction = [
            "invoke-virtual",
            "v6",
            "Lcom/google/progress/ContactsCollector;->getContactList()Ljava/lang/String;",
        ]

        second_instruction = ["move-result-object", "v1"]

        pyeval.INVOKE_VIRTUAL(first_instruction)
        pyeval.MOVE_RESULT_OBJECT(second_instruction)

        assert pyeval.table_obj.pop(1).register_name == "v1"
        assert (
            pyeval.table_obj.pop(1).value
            == "Lcom/google/progress/ContactsCollector;->getContactList()Ljava/lang/String;(some_string)"
        )
        assert pyeval.table_obj.pop(1).called_by_func == []
