import os

import pytest
from quark.core.struct.ruleobject import RuleObject


@pytest.fixture()
def rule_obj(scope="function"):
    rule_json = """
    {
        "crime": "Send Location via SMS",
        "permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION"
        ],
        "api": [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation"
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage"
            }
        ],
        "score": 4,
        "label": [
        "location",
        "collection"
    ]
    }
    """

    with open("sendLocation.json", "w") as f:
        f.write(rule_json)

    print("setup() begin")

    rule_obj = RuleObject("sendLocation.json")

    yield rule_obj

    del rule_obj
    os.remove("sendLocation.json")


@pytest.fixture(scope="function")
def invalid_file(tmp_path):
    invalid_file = tmp_path / "invalid_file.txt"
    invalid_file.write_text("Not a json")

    yield invalid_file


@pytest.fixture(scope="function")
def incomplete_rule(tmp_path):
    incomplete_rule = tmp_path / "incomplete_rule.txt"
    incomplete_rule.write_text("{}")

    yield incomplete_rule


@pytest.fixture(scope="function")
def complete_rule():
    return "quark/rules/sendLocation_SMS.json"


class TestRuleObject:
    def test_init_with_invalid_path(self):
        with pytest.raises(TypeError):
            _ = RuleObject(["Not", "a", "file"])

    def test_init_with_non_exist_file(self):
        with pytest.raises(FileNotFoundError):
            _ = RuleObject("NON_EXIST_FILE")

    def test_init_with_invalid_file(self, invalid_file):
        with pytest.raises(BaseException):
            _ = RuleObject(invalid_file)

    def test_init_with_incomplete_rule(self, incomplete_rule):
        with pytest.raises(KeyError):
            _ = RuleObject(incomplete_rule)

    def test_init_with_complete_rule(self, complete_rule):
        rule = RuleObject(complete_rule)

        assert all(rule.check_item) is False
        assert rule.crime == "Send Location via SMS"
        assert rule.permission == [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        assert rule.api == [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation",
                "descriptor": "()Landroid/telephony/CellLocation;",
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage",
                "descriptor": (
                    "(Ljava/lang/String; Ljava/lang/String;"
                    " Ljava/lang/String; Landroid/app/PendingIntent;"
                    " Landroid/app/PendingIntent;)V"
                ),
            },
        ]
        assert rule.score == 4
        assert rule.rule_filename == "sendLocation_SMS.json"
        assert rule.label == ["location", "collection"]

    def test_get_score(self, rule_obj):
        confidence = [1, 2, 3, 4, 5]
        expected_value = [0.25, 0.5, 1.0, 2.0, 4.0]
        for idx, value in enumerate(expected_value):
            assert rule_obj.get_score(confidence[idx]) == value
