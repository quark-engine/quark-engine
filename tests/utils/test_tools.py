import json

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


def test_write_json_report(tmpdir):
    content_dict = {
        "test": "test",
    }
    tfile = tmpdir.join('test_write_report.json')
    content_json = json.dumps(content_dict)
    assert tools.write_json_report(tfile, content_dict) == True
    assert tools.write_json_report(tfile, "asdf") == False


def test_hash_apk():
    apk = "quark/sample/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
    hashed = tools.hash_apk(apk)
    assert hashed == "1e80ac341a665e8984f07bec7f351e18"
