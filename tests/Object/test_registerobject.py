import pytest
from quark.Objects.registerobject import RegisterObject


@pytest.fixture()
def standard_register_obj():
    register_obj = RegisterObject("v1", "value", "func")
    yield register_obj

    del register_obj


class TestRegisterObject:
    def test_init_without_called_by_func(self):
        register_obj = RegisterObject("v1", "value")

        assert register_obj._register_name == "v1"
        assert register_obj._value == "value"
        assert register_obj._called_by_func == []

    def test_init_with_called_by_func(self):
        register_obj = RegisterObject("v1", "value", "func")

        assert register_obj._register_name == "v1"
        assert register_obj._value == "value"
        assert register_obj._called_by_func == ["func"]

    def test_called_by_func(self, standard_register_obj):
        value = "func1"

        standard_register_obj.called_by_func = value

        assert len(standard_register_obj.called_by_func) == 2
        assert list(standard_register_obj.called_by_func)[-1] == value

    def test_register_name(self):
        value = "v1"

        standard_register_obj.register_name = value

        assert standard_register_obj.register_name == value

    def test_value(self):
        value = "value"

        standard_register_obj.value = value

        assert standard_register_obj.value == value

    def test_hash_index(self, standard_register_obj):
        standard_register_obj._register_name = "v5"

        assert standard_register_obj.hash_index == 5
