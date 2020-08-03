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

def test_output_json_report():
    pass

def test_hash_apk():
    apk = "quark/sample/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
    hashed = tools.hash_apk(apk)
    assert hashed == "228e236646ec70aa24e7e1c7b1ec81b4496d2fb16a2b7ae0dd843c704df14a5a88ef471c217125391084b9137bffdcf8afdd2ba7a581ea0bf28cfe15dcea18e2"
    
    
