import os

import pytest

from quark.Objects.quarkrule import QuarkRule


@pytest.fixture()
def rule_obj(scope="function"):
    rule_json = """
    {
        "crime": "Send Location via SMS",
        "x1_permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION"
        ],
        "x2n3n4_comb": [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation"
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage"
            }
        ],
        "yscore": 4
    }
    """

    with open("sendLocation.json", "w") as f:
        f.write(rule_json)

    print("setup() begin")

    rule_obj = QuarkRule("sendLocation.json")

    yield rule_obj

    del rule_obj
    os.remove("sendLocation.json")


class TestRuleObject:
    def test_init(self, rule_obj):
        assert rule_obj.crime == "Send Location via SMS"

        expected_permissions = [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
        ]

        assert rule_obj.x1_permission == expected_permissions

        expected_x2n3n4_comb = [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation",
            },
            {"class": "Landroid/telephony/SmsManager", "method": "sendTextMessage"},
        ]

        assert rule_obj.x2n3n4_comb == expected_x2n3n4_comb

        assert rule_obj.yscore == 4

    def test_get_score(self, rule_obj):

        confidence = [1, 2, 3, 4, 5]
        expected_value = [0.25, 0.5, 1.0, 2.0, 4.0]
        for idx, value in enumerate(expected_value):
            assert rule_obj.get_score(confidence[idx]) == value
