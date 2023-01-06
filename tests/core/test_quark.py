import base64
import json
import os
from unittest.mock import patch

import pytest
import requests

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject

APK_SOURCE = (
    "https://github.com/quark-engine/apk-samples"
    "/raw/master/malware-samples/14d9f1a92dd984d6040cc41ed06e273e.apk"
)
APK_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"


@pytest.fixture(scope="function")
def simple_quark_obj():
    r = requests.get(APK_SOURCE, allow_redirects=True)
    open(APK_FILENAME, "wb").write(r.content)

    apk_file = APK_FILENAME
    return Quark(apk_file)


@pytest.fixture(scope="function")
def quark_obj(simple_quark_obj):
    data = simple_quark_obj
    # rule
    rules = "quark/rules"
    rules_list = os.listdir(rules)
    for single_rule in rules_list:
        if single_rule.endswith("json"):
            rulepath = os.path.join(rules, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)
            data.generate_json_report(rule_checker)

    yield data


@pytest.fixture(scope="function")
def rule_without_keyword(tmp_path):
    rule_file = tmp_path / "rule_without_keyword.json"

    data = base64.b64decode(
        """eyAiY3JpbWUiOiAiUmVhZCBzZW5zaXRpdmUgZGF0YShTTVMsIENBTExMT0csIGV0YykiLCAicGVy
bWlzc2lvbiI6IFtdLCAiYXBpIjogWyB7ICJkZXNjcmlwdG9yIjogIigpTGFuZHJvaWQvY29udGVu
dC9Db250ZW50UmVzb2x2ZXI7IiwgImNsYXNzIjogIkxhbmRyb2lkL2NvbnRlbnQvQ29udGV4dDsi
LCAibWV0aG9kIjogImdldENvbnRlbnRSZXNvbHZlciIgfSwgeyAiZGVzY3JpcHRvciI6ICIoTGFu
ZHJvaWQvbmV0L1VyaTsgW0xqYXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzsgW0xq
YXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzspTGFuZHJvaWQvZGF0YWJhc2UvQ3Vy
c29yOyIsICJjbGFzcyI6ICJMYW5kcm9pZC9jb250ZW50L0NvbnRlbnRSZXNvbHZlcjsiLCAibWV0
aG9kIjogInF1ZXJ5IiB9IF0sICJzY29yZSI6IDEsICJsYWJlbCI6IFsgImNvbGxlY3Rpb24iLCAi
c21zIiwgImNhbGxsb2ciLCAiY2FsZW5kYXIiIF0gfQ=="""
    ).decode()

    rule_file.write_text(data)
    return rule_file


@pytest.fixture(scope="function")
def rule_with_one_keyword(tmp_path):
    rule_file = tmp_path / "rule_without_keyword.json"

    data = base64.b64decode(
        """eyAiY3JpbWUiOiAiUmVhZCBzZW5zaXRpdmUgZGF0YShTTVMsIENBTExMT0csIGV0YykiLCAicGVy
bWlzc2lvbiI6IFtdLCAiYXBpIjogWyB7ICJkZXNjcmlwdG9yIjogIigpTGFuZHJvaWQvY29udGVu
dC9Db250ZW50UmVzb2x2ZXI7IiwgImNsYXNzIjogIkxhbmRyb2lkL2NvbnRlbnQvQ29udGV4dDsi
LCAibWV0aG9kIjogImdldENvbnRlbnRSZXNvbHZlciIgfSwgeyAiZGVzY3JpcHRvciI6ICIoTGFu
ZHJvaWQvbmV0L1VyaTsgW0xqYXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzsgW0xq
YXZhL2xhbmcvU3RyaW5nOyBMamF2YS9sYW5nL1N0cmluZzspTGFuZHJvaWQvZGF0YWJhc2UvQ3Vy
c29yOyIsICJjbGFzcyI6ICJMYW5kcm9pZC9jb250ZW50L0NvbnRlbnRSZXNvbHZlcjsiLCAibWV0
aG9kIjogInF1ZXJ5IiwgImtleXdvcmQiOiBbICJjb250ZW50Oi8vY2FsbF9sb2cvY2FsbHMiIF0g
fSBdLCAic2NvcmUiOiAxLCAibGFiZWwiOiBbICJjb2xsZWN0aW9uIiwgInNtcyIsICJjYWxsbG9n
IiwgImNhbGVuZGFyIiBdIH0="""
    ).decode()

    rule_file.write_text(data)
    return rule_file


class TestQuark:
    @pytest.mark.skip(reason="discussion needed.")
    def test_find_previous_method_with_invalid_types(self, quark_obj):
        with pytest.raises(TypeError):
            quark_obj.find_previous_method(None, None, None)

    def test_find_previous_method_without_result(self, quark_obj):
        parent_function = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )
        base_method = quark_obj.apkinfo.find_method(
            "Landroid/telephony/TelephonyManager",
            "getCellLocation",
            "()Landroid/telephony/CellLocation;",
        )
        wrapper = []

        quark_obj.find_previous_method(base_method, parent_function, wrapper)

        assert wrapper == list()

    def test_find_previous_method_with_result(self, quark_obj):
        parent_function = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )

        wrapper = []

        base_method = quark_obj.apkinfo.find_method(
            "Landroid/telephony/TelephonyManager",
            "getCellLocation",
            "()Landroid/telephony/CellLocation;",
        )

        expect_method_analysis = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )

        expected_list = [expect_method_analysis]

        quark_obj.find_previous_method(base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

    def test_find_intersection_with_invalid_type(self, quark_obj):
        with pytest.raises(ValueError):
            quark_obj.find_intersection(None, None)

    def test_find_intersection_with_empty_set(self, quark_obj):
        first_method_set = set()
        second_method_set = set()

        with pytest.raises(ValueError):
            quark_obj.find_intersection(first_method_set, second_method_set)

    @pytest.mark.skip(reason="discussion needed.")
    def test_find_intersection_with_set_containing_invalid_type(self, quark_obj):
        first_method_set = {1, 2, 3}
        second_method_set = {4, 5, 6}

        with pytest.raises(TypeError):
            quark_obj.find_intersection(first_method_set, second_method_set)

    def test_find_intersection_with_result(self, quark_obj):
        location_api = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )
        location_api_upper = quark_obj.apkinfo.upperfunc(location_api)

        sms_api = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )
        sms_api_upper = quark_obj.apkinfo.upperfunc(sms_api)

        with pytest.raises(ValueError, match="Set is Null"):
            quark_obj.find_intersection(set(), set())
            quark_obj.find_intersection(set(), {1})
            quark_obj.find_intersection({1}, set())

        assert len(location_api_upper & sms_api_upper) == 3

        # When there is no intersection in first layer, it will try to enter
        # the second layer to check the intersection.

        # Send Location via SMS
        expected_result_location = {
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService;", "doByte", "([B)V"
            ),
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
            ),
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
            ),
        }

        assert (
            quark_obj.find_intersection(location_api_upper, sms_api_upper)
            == expected_result_location
        )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_sequence_with_invalid_type(self, quark_obj):
        mutual_parent = None
        first_method_list = None
        second_method_list = None

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_sequence_with_lists_containing_invalid_type(self, quark_obj):
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )
        first_method_list = [1, 2, 3]
        second_method_list = [4, 5, 6]

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    def test_check_sequence_is_true(self, quark_obj):
        # Send Location via SMS

        location_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
        )
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )

        mutual_parent_true = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )

        result = quark_obj.check_sequence(
            mutual_parent_true,
            [location_method],
            [sendSms_method],
        )

        assert result is True

    def test_check_sequence_with_contact_method(self, quark_obj):
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/SMSHelper;",
            "sendSms",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        )

        mutual_parent_true = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )

        contact_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )

        result = quark_obj.check_sequence(
            mutual_parent_true,
            [contact_method],
            [sendSms_method],
        )

        assert result is True

    def test_check_sequence_is_false(self, quark_obj):
        # Send Location via SMS
        sendSms_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
        )

        mutual_parent_false = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
        )

        # # Send contact via SMS

        contact_method = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;",
        )

        result = quark_obj.check_sequence(
            mutual_parent_false,
            [contact_method],
            [sendSms_method],
        )

        assert result is False

    def test_check_parameter_with_invalid_type(self, quark_obj):
        mutual_parent = None
        first_method_list = None
        second_method_list = None

        with pytest.raises(TypeError):
            quark_obj.check_parameter(
                mutual_parent, first_method_list, second_method_list
            )

    @pytest.mark.skip(reason="discussion needed.")
    def test_check_parameter_with_lists_containing_invalid_type(self, quark_obj):
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )
        first_method_list = [1, 2, 3]
        second_method_list = [4, 5, 6]

        with pytest.raises(TypeError):
            quark_obj.check_sequence(
                mutual_parent, first_method_list, second_method_list
            )

    def test_check_parameter_is_True(self, quark_obj):
        second_method = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/SMSHelper;",
                "sendSms",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            )
        ]
        first_method = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;"
            )
        ]
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )

        assert (
            quark_obj.check_parameter(mutual_parent, first_method, second_method)
            == True
        )

    def test_check_parameter_is_False(self, quark_obj):
        first_method_list = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService$2;", "run", "()V"
            )
        ]

        second_method_list = [
            quark_obj.apkinfo.find_method(
                "Lcom/google/progress/ContactsCollecter;",
                "getContactList",
                "()Ljava/lang/String;",
            )
        ]
        mutual_parent = quark_obj.apkinfo.find_method(
            "Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"
        )

        result = quark_obj.check_parameter(
            mutual_parent, first_method_list, second_method_list
        )

        assert result is False

    def test_check_parameter_values_with_no_keyword_rule(
        self, simple_quark_obj, rule_without_keyword
    ):
        rule_object = RuleObject(rule_without_keyword)

        with patch("quark.core.quark.Quark.check_parameter_values") as mock:
            simple_quark_obj.run(rule_object)
            mock.assert_not_called()

    def test_check_parameter_values_with_one_keyword_rule(
        self, simple_quark_obj, rule_with_one_keyword
    ):
        rule_object = RuleObject(rule_with_one_keyword)

        with patch("quark.core.quark.Quark.check_parameter_values") as mock:
            simple_quark_obj.run(rule_object)
            mock.assert_called()

    def test_check_parameter_values_without_matched_str(self, simple_quark_obj):
        source_str = (
            "Landroid/content/ContentResolver;->query(Landroid/net/Uri;"
            " [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String;"
            " Ljava/lang/String;)Landroid/database/Cursor;"
            "(Landroid/content/Context;"
            "->getContentResolver()Landroid/content/ContentResolver;"
            "(Lahmyth/mine/king/ahmyth/MainService;->getContextOfApplication()"
            "Landroid/content/Context;()),Landroid/net/Uri;"
            "->parse(Ljava/lang/String;)"
            "Landroid/net/Uri;(file://usr/bin/su),v0,v0,v0,v0)"
        )
        pattern_list = (
            (
                "Landroid/content/ContentResolver;->query(Landroid/net/Uri;"
                " [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String;"
                " Ljava/lang/String;)Landroid/database/Cursor;"
            ),
        )
        keyword_item_list = [("content://call_log/calls",)]

        result = simple_quark_obj.check_parameter_values(
            source_str, pattern_list, keyword_item_list
        )

        assert bool(result) is False

    def test_check_parameter_values_with_matched_str(self, simple_quark_obj):
        source_str = (
            "Landroid/database/Cursor;->getColumnIndex"
            "(Ljava/lang/String;)I(Landroid/content/ContentResolver;"
            "->query(Landroid/net/Uri; [Ljava/lang/String; Ljava/lang/String;"
            " [Ljava/lang/String; Ljava/lang/String;)Landroid/database/Cursor;"
            "(Landroid/content/Context;->getContentResolver()"
            "Landroid/content/ContentResolver;(Lahmyth/mine/king/ahmyth"
            "/MainService;->getContextOfApplication()Landroid/content/"
            "Context;()),Landroid/net/Uri;->parse(Ljava/lang/String;)"
            "Landroid/net/Uri;(content://call_log/calls),v0,v0,v0,v0),number)"
        )
        pattern_list = (
            "Landroid/content/ContentResolver;->query(Landroid/net/Uri;"
            " [Ljava/lang/String; Ljava/lang/String; [Ljava/lang/String;"
            " Ljava/lang/String;)Landroid/database/Cursor;",
        )
        keyword_item_list = [("content://call_log/calls",)]

        result = simple_quark_obj.check_parameter_values(
            source_str, pattern_list, keyword_item_list
        )

        assert bool(result) is True

    def test_get_json_report(self, quark_obj):
        json_report = quark_obj.get_json_report()
        # Check if proper dict object
        assert isinstance(json_report, dict)
        assert json_report.get("md5") == "14d9f1a92dd984d6040cc41ed06e273e"

    def test_json_report_format(self, quark_obj):
        # Inner function for comparing two json objects
        def sorting(item):
            if isinstance(item, dict):
                return sorted((key, sorting(values)) for key, values in item.items())
            if isinstance(item, list):
                return sorted(sorting(x) for x in item)
            else:
                return item

        json_report = quark_obj.get_json_report()

        with open("tests/core/json_report_sample.json") as json_file:
            sample_json = json.loads(json_file.read())

            assert sorting(sample_json) == sorting(json_report)
