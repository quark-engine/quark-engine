from quark.utils import tools


def test_remove_dup_list():
    assert tools.remove_dup_list([]) == []
    assert tools.remove_dup_list([1, 2, 3, 4, 3, 4, 2]) == [1, 2, 3, 4]
    assert len(tools.remove_dup_list([1, 2, 3, 4, 3, 4, 2])) == 4
    assert set(tools.remove_dup_list(["hello", "test", "test"])) == {
        "hello", "test",
    }
    assert len(tools.remove_dup_list(["hello", "test", "test"])) == 2
    assert tools.remove_dup_list([2.0, 30, 4.0, 2.0]) == [2.0, 4.0, 30]
    assert len(tools.remove_dup_list([2.0, 30, 4.0, 2.0])) == 3
    assert tools.remove_dup_list([1, 2, 3]) == [1, 2, 3]
