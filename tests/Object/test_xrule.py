import pytest

from quark.Objects.XRule import XRule


@pytest.fixture()
def xrule(scope="function"):
    apk_file = "quark/sample/14d9f1a92dd984d6040cc41ed06e273e.apk"
    xrule = XRule(apk_file)
    yield xrule


class TestXRule():

    def test_find_previous_method(self, xrule):
        base_method = ("Lcom/google/progress/SMSHelper;", "sendSms")
        top_method = ("Lcom/google/progress/AndroidClientService;", "sendMessage")
        expected_list = [("Lcom/google/progress/SMSHelper;", "sendSms")]

        test_list = []

        xrule.find_previous_method(base_method, top_method, test_list)

        assert test_list == expected_list
