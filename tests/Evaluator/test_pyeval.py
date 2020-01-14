import pytest

from quark.Evaluator.pyeval import PyEval, MAX_REG_COUNT
from quark.Objects.tableobject import TableObject
from quark.Objects.variableobject import VarabileObject


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
    v4_mock_variable_obj = VarabileObject(
        "v4", "Lcom/google/progress/SMSHelper;", None)
    v9_mock_variable_obj = VarabileObject(
        "v9", "some_string", "java.io.file.close()")
    pyeval.table_obj.insert(4, v4_mock_variable_obj)
    pyeval.table_obj.insert(9, v9_mock_variable_obj)

    yield pyeval

    del pyeval


class TestPyEval(object):
    def test_init(self, pyeval):
        assert len(pyeval.table_obj.hash_table) == MAX_REG_COUNT
        assert isinstance(pyeval.table_obj, TableObject)
        assert pyeval.ret_stack == []

        assert pyeval.table_obj.pop(4).register_name == "v4"
        assert pyeval.table_obj.pop(
            4).value == "Lcom/google/progress/SMSHelper;"
        assert pyeval.table_obj.pop(4).called_by_func == []

        assert pyeval.table_obj.pop(9).register_name == "v9"
        assert pyeval.table_obj.pop(9).value == "some_string"
        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()"]

    def test_invoke_direct(self, pyeval):
        instruction = ["invoke-direct", "v4", "v9", "some_function()"]

        pyeval.INVOKE_DIRECT(instruction)

        # It should be [some_function()(v4, v9)], and the query the value of v4
        # and v9 and replace it with the value into
        # [some_function()(Lcom/google/progress/SMSHelper;,some_string)]

        v4_expected_call_by_func = [
            "some_function()(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        v9_expected_call_by_func = [
            "java.io.file.close()",
            "some_function()(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.table_obj.pop(
            4).called_by_func == v4_expected_call_by_func
        assert pyeval.table_obj.pop(
            9).called_by_func == v9_expected_call_by_func

    def test_invoke_virtual(self, pyeval):
        instruction = ["invoke-virtual", "v4", "v9", "some_function()"]

        pyeval.INVOKE_VIRTUAL(instruction)
        # It should be [some_function()(v4, v9)], and the query the value of v4
        # and v9 and replace it with the value into
        # [some_function()(Lcom/google/progress/SMSHelper;,some_string)]

        v4_expected_call_by_func = [
            "some_function()(Lcom/google/progress/SMSHelper;,some_string)"
        ]
        v9_expected_call_by_func = [
            "java.io.file.close()",
            "some_function()(Lcom/google/progress/SMSHelper;,some_string)",
        ]
        assert pyeval.table_obj.pop(
            4).called_by_func == v4_expected_call_by_func
        assert pyeval.table_obj.pop(
            9).called_by_func == v9_expected_call_by_func

    def test_move_result_object(self, pyeval):
        v6_mock_variable_obj = VarabileObject("v6", "some_string", None)

        pyeval.table_obj.insert(6, v6_mock_variable_obj)

        assert pyeval.table_obj.pop(6).register_name == "v6"
        assert pyeval.table_obj.pop(6).value == "some_string"
        assert pyeval.table_obj.pop(6).called_by_func == []

        first_instruction = [
            "invoke-virtual",
            "v6",
            "Lcom/google/progress/ContactsCollecter;->getContactList()Ljava/lang/String;",
        ]

        second_instruction = ["move-result-object", "v1"]

        pyeval.INVOKE_VIRTUAL(first_instruction)
        pyeval.MOVE_RESULT_OBJECT(second_instruction)

        assert pyeval.table_obj.pop(1).register_name == "v1"
        assert (
            pyeval.table_obj.pop(1).value
            == "Lcom/google/progress/ContactsCollecter;->getContactList()Ljava/lang/String;(some_string)"
        )
        assert pyeval.table_obj.pop(1).called_by_func == []

    def test_new_instance(self, pyeval):
        instruction = ["new-instance", "v3", "Lcom/google/progress/SMSHelper;"]

        override_original_instruction = [
            "new-instance", "v4", "override_value"]

        pyeval.NEW_INSTANCE(instruction)

        assert pyeval.table_obj.pop(3).register_name == "v3"
        assert pyeval.table_obj.pop(
            3).value == "Lcom/google/progress/SMSHelper;"
        assert pyeval.table_obj.pop(3).called_by_func == []

        assert pyeval.table_obj.pop(4).register_name == "v4"
        assert pyeval.table_obj.pop(
            4).value == "Lcom/google/progress/SMSHelper;"
        assert pyeval.table_obj.pop(4).called_by_func == []

        pyeval.NEW_INSTANCE(override_original_instruction)

        assert pyeval.table_obj.pop(4).register_name == "v4"
        assert pyeval.table_obj.pop(4).value == "override_value"
        assert pyeval.table_obj.pop(4).called_by_func == []

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

    def test_const_four(self, pyeval):
        instruction = [
            "const/4",
            "v8",
            "https://github.com/quark-engine/quark-engine"]

        pyeval.CONST_FOUR(instruction)

        assert pyeval.table_obj.pop(8).register_name == "v8"
        assert (
            pyeval.table_obj.pop(8).value
            == "https://github.com/quark-engine/quark-engine"
        )
        assert pyeval.table_obj.pop(8).called_by_func == []

    def test_aget_object(self, pyeval):
        """
        aget-object vx,vy,vz

        It means vx = vy[vz].
        """
        v2_mock_variable_obj = VarabileObject(
            "v2", "some_list_like[1,2,3,4]", "java.io.file.close()"
        )
        v3_mock_variable_obj = VarabileObject("v3", "2", None)
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

        assert isinstance(pyeval.show_table()[4][0], VarabileObject)
        assert isinstance(pyeval.show_table()[9][0], VarabileObject)
