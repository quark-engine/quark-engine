import os
import pytest
import requests

from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule

APK_SOURCE = (
    "https://github.com/quark-engine/apk-malware-samples"
    "/raw/master/14d9f1a92dd984d6040cc41ed06e273e.apk"
)
APK_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"


@pytest.fixture()
def quark_obj(scope="function"):
    r = requests.get(APK_SOURCE, allow_redirects=True)
    open(APK_FILENAME, "wb").write(r.content)

    apk_file = APK_FILENAME
    data = Quark(apk_file)
    # rule
    rules = "quark/rules"
    rules_list = os.listdir(rules)
    for single_rule in rules_list:
        if single_rule.endswith("json"):
            rulepath = os.path.join(rules, single_rule)
            rule_checker = QuarkRule(rulepath)

            # Run the checker
            data.run(rule_checker)
            data.generate_json_report(rule_checker)

    yield data


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

    def test_get_json_report(self, quark_obj):
        json_report = quark_obj.get_json_report()
        # Check if proper dict object
        assert isinstance(json_report, dict)
        assert json_report.get("md5") == "14d9f1a92dd984d6040cc41ed06e273e"
