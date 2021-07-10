import itertools
from unittest.mock import patch

import pytest
from quark.Evaluator.pyeval import MAX_REG_COUNT, PyEval
from quark.Objects.struct.registerobject import RegisterObject
from quark.Objects.struct.tableobject import TableObject


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


@pytest.fixture(scope="function")
def pyeval():
    pyeval = PyEval()

    # mock_hash_table = [...[], [v4_mock_variable_obj], [], [],
    # [v9_mock_variable_obj]....]
    v4_mock_variable_obj = RegisterObject(
        "v4",
        "Lcom/google/progress/SMSHelper;",
        None,
    )
    v5_mock_variable_obj = RegisterObject(
        "v5", "some_number", "java.lang.String.toString()"
    )
    v6_mock_variable_obj = RegisterObject(
        "v6", "an_array", "java.lang.Collection.toArray()"
    )
    v7_mock_variable_obj = RegisterObject("v7", "a_float")
    v9_mock_variable_obj = RegisterObject(
        "v9",
        "some_string",
        "java.io.file.close()",
    )
    pyeval.table_obj.insert(4, v4_mock_variable_obj)
    pyeval.table_obj.insert(5, v5_mock_variable_obj)
    pyeval.table_obj.insert(6, v6_mock_variable_obj)
    pyeval.table_obj.insert(7, v7_mock_variable_obj)
    pyeval.table_obj.insert(9, v9_mock_variable_obj)

    yield pyeval

    del pyeval


MOVE_KIND = [
    prefix + postfix
    for prefix, postfix in itertools.product(
        ["move", "move-object"], ["", "/from16", "/16"]
    )
] + ["array-length"]
MOVE_WIDE_KIND = ["move-wide" + postfix for postfix in ["", "/from16", "/16"]]


@pytest.fixture(scope="module", params=MOVE_KIND)
def move_kind(request):
    return request.param


@pytest.fixture(scope="module", params=MOVE_WIDE_KIND)
def move_wide_kind(request):
    return request.param


FILLED_ARRAY_KIND = ("filled-new-array", "filled-new-array/range")


@pytest.fixture(scope="module", params=FILLED_ARRAY_KIND)
def filled_array_kind(request):
    return request.param


AGET_KIND = [
    "aget" + postfix
    for postfix in ("-object", "-byte", "-char", "-short", "-boolean")
]
AGET_WIDE_KIND = "aget-wide"


@pytest.fixture(scope="module", params=AGET_KIND)
def aget_kind(request):
    return request.param


@pytest.fixture(scope="module", params=AGET_KIND)
def aget_wide_kind(request):
    return request.param


APUT_KIND = [
    "aput" + postfix
    for postfix in ("-object", "-byte", "-char", "-short", "-boolean")
]
APUT_WIDE_KIND = ("aput-wide",)


@pytest.fixture(scope="module", params=APUT_KIND)
def aput_kind(request):
    return request.param


@pytest.fixture(scope="module", params=APUT_WIDE_KIND)
def aput_wide_kind(request):
    return request.param

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

        assert pyeval.table_obj.pop(9).called_by_func == [
            "java.io.file.close()"
        ]
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

    # Tests for invoke polymorphic
    def test_invoke_polymorphic_with_valid_mnemonic(self, pyeval):
        instruction = [
            "invoke-polymorphic",
            "v4",
            "v9",
            "some_function()V",
            "prototype_idx",
        ]

        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_POLYMORPHIC(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for invoke-custom
    def test_invoke_custom_with_valid_mnemonic(self, pyeval):
        instruction = ["invoke-custom", "v4", "v9", "method"]
        with patch("quark.Evaluator.pyeval.PyEval._invoke") as mock:
            pyeval.INVOKE_CUSTOM(instruction)
            mock.assert_called_once_with(instruction)

    # Tests for _move_result
    def test_move_with_non_list_object(self, pyeval):
        instruction = None

        with pytest.raises(TypeError):
            pyeval._move_result(instruction)

    def test_move_with_empty_list(self, pyeval):
        instruction = []

        with pytest.raises(IndexError):
            pyeval._move_result(instruction)

    def test_move_with_invalid_instrcution(self, pyeval):
        instruction = ["move-kind", "", ""]

        with pytest.raises(ValueError):
            pyeval._move_result(instruction)

    def test_move_with_valid_instrcution(self, pyeval):
        instruction = ["move-result-object", "v1"]
        expected_return_value = (
            "some_function()V(used_register_1, used_register_2)"
        )
        pyeval.ret_stack.append(expected_return_value)

        pyeval._move_result(instruction)

        assert pyeval.table_obj.pop(1).value == expected_return_value
        assert pyeval.table_obj.pop(1).called_by_func == []

    # Tests for move_result
    def test_move_result_with_valid_mnemonic(self, pyeval):
        instruction = ["move-result", "v1"]

        with patch("quark.Evaluator.pyeval.PyEval._move_result") as mock:
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

        with patch("quark.Evaluator.pyeval.PyEval._move_result") as mock:
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

    def test_const_string_jumbo(self, pyeval):
        instruction = [
            "const-string/jumbo",
            "v8",
            "https://github.com/quark-engine/quark-engine",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(8) == RegisterObject(
            "v8", "https://github.com/quark-engine/quark-engine"
        )

    def test_const_class(self, pyeval):
        instruction = [
            "const-class",
            "v8",
            "Ljava/lang/Object;->toString()",
        ]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(8) == RegisterObject(
            "v8", "Ljava/lang/Object;->toString()"
        )

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

    # Tests for move-kind
    def test_move_kind(self, pyeval, move_kind):
        instruction = [move_kind, "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "v1", "Lcom/google/progress/SMSHelper;"
        )

    def test_move_wide_kind(self, pyeval, move_wide_kind):
        instruction = [move_wide_kind, "v1", "v4"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "v1", "Lcom/google/progress/SMSHelper;"
        )
        assert pyeval.table_obj.pop(2) == RegisterObject("v2", "some_number")

    # Tests for filled-array-kind
    def test_filled_array_kind(self, pyeval, filled_array_kind):
        instruction = [filled_array_kind, "v1", "type_idx"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.ret_stack == ["new-array[()"]

    # Tests for aget-kind
    def test_aget_kind(self, pyeval, aget_kind):
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

        instruction = [aget_kind, "v1", "v2", "v3"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "v1", "some_list_like[1,2,3,4][2]"
        )

    def test_aget_wide_kind(self, pyeval, aget_wide_kind):
        instruction = [aget_wide_kind, "v1", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "v1", "an_array[some_number]"
        )

    # Tests for aput-kind
    def test_aput_kind(self, pyeval, aput_kind):
        instruction = [aput_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            "v6",
            "an_array[some_number]:Lcom/google/progress/SMSHelper;",
        )

    def test_aput_wide_kind(self, pyeval, aput_wide_kind):
        instruction = [aput_wide_kind, "v4", "v6", "v5"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(6) == RegisterObject(
            "v6",
            "an_array[some_number]:(Lcom/google/progress/SMSHelper;, some_number)",
        )


    # Tests for fill-array-data
    def test_fill_array_data(self, pyeval):
        instruction = ["fill-array-data", "v1", "array-data-address"]

        pyeval.eval[instruction[0]](instruction)

        assert pyeval.table_obj.pop(1) == RegisterObject(
            "v1", "Embedded-array-data"
        )

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
