import pytest

from quark.Objects.tableobject import TableObject


@pytest.fixture()
def table_obj():
    table_obj = TableObject(5)

    yield table_obj

    del table_obj


class TestTableObject:
    def test_init_with_no_arg(self):
        with pytest.raises(TypeError):
            _ = TableObject()

    def test_init_with_non_numeric(self):
        with pytest.raises(TypeError):
            _ = TableObject(None)

    def test_init_with_valid_arg(self):
        table_obj = TableObject(5)

        assert isinstance(table_obj, TableObject)
        assert len(table_obj.hash_table) == 5
        assert table_obj.hash_table == [[], [], [], [], []]

    def test_insert_with_non_numeric(self, table_obj):
        with pytest.raises(TypeError):
            table_obj.insert(None)

    def test_insert_with_number_once(self, table_obj):
        index, data = 1, "Value"

        table_obj.insert(index, data)

        assert table_obj.hash_table[index] == [data]

    def test_insert_with_number_twice(self, table_obj):
        table_obj.insert(0, "first")
        table_obj.insert(0, "second")

        assert table_obj.hash_table[0] == ["first", "second"]

    def test_insert_with_num_beyond_max(self, table_obj):
        index, data = 6, "Max value"

        table_obj.insert(6, data)

    def test_get_obj_list_before_insertion(self, table_obj):
        assert table_obj.get_obj_list(3) == []

    def test_get_obj_list_after_insertion(self, table_obj):
        table_obj.insert(3, "test_value")

        assert table_obj.get_obj_list(3) == ["test_value"]

    def test_get_table(self, table_obj):
        assert table_obj.hash_table == table_obj.get_table()

    def test_pop_none(self, table_obj):
        with pytest.raises(IndexError):
            _ = table_obj.pop(1)

    def test_pop_value(self, table_obj):
        table_obj.insert(4, "one")
        table_obj.insert(4, "two")
        table_obj.insert(4, "three")

        assert table_obj.pop(4) == "three"
        assert table_obj.get_obj_list(4) == ["one", "two", "three"]
