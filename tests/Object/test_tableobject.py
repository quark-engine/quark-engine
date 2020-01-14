import pytest

from quark.Objects.tableobject import TableObject


@pytest.fixture()
def table_obj():
    table_obj = TableObject(5)

    yield table_obj

    del table_obj


class TestTableObject(object):

    def test_init(self, table_obj):
        with pytest.raises(TypeError):
            table_obj_with_no_argu = TableObject()

        assert isinstance(table_obj, TableObject)
        assert table_obj.hash_table == [[], [], [], [], []]
        assert len(table_obj.hash_table) == 5

    def test_insert(self, table_obj):
        table_obj.insert(2, "test_insert_value")
        table_obj.insert(0, "first")
        table_obj.insert(0, "second")
        with pytest.raises(IndexError):
            table_obj.insert(5, "show IndexError")

        assert table_obj.hash_table[2] == ["test_insert_value"]
        assert table_obj.hash_table[0] == ["first", "second"]

    def test_get_obj_list(self, table_obj):
        table_obj.insert(3, "test_value")

        with pytest.raises(IndexError):
            table_obj.insert(6, "show IndexError")

        assert table_obj.get_obj_list(3) == ["test_value"]
        assert table_obj.hash_table[3] == ["test_value"]

    def test_get_table(self, table_obj):
        assert table_obj.hash_table == table_obj.get_table()

    def test_pop(self, table_obj):
        table_obj.insert(4, "one")
        table_obj.insert(4, "two")
        table_obj.insert(4, "three")

        assert table_obj.pop(4) == "three"
        assert table_obj.get_obj_list(4) == ["one", "two", "three"]
