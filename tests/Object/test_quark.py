import pytest

from quark.Objects.quark import Quark


@pytest.fixture()
def result(scope="function"):
    apk_file = "quark/sample/14d9f1a92dd984d6040cc41ed06e273e.apk"
    data = Quark(apk_file)
    yield data


class TestQuark():

    def test_find_previous_method(self, result):
        # Test Case 1

        parent_function = result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage", "()V")
        expect_method_analysis = result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms",
                                                            "(Ljava/lang/String; Ljava/lang/String;)I")

        first_base_method = result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms",
                                                       "(Ljava/lang/String; Ljava/lang/String;)I")

        expected_list = [expect_method_analysis]

        wrapper = []

        result.find_previous_method(first_base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

        # Test Case 2

        wrapper = []

        second_base_method = result.apkinfo.find_method("Landroid/telephony/TelephonyManager", "getCellLocation",
                                                        "()Landroid/telephony/CellLocation;")

        expect_method_analysis = result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation",
                                                            "()Ljava/lang/String;")

        expected_list = [expect_method_analysis]

        result.find_previous_method(second_base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

    def test_find_intersection(self, result):
        location_api = result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation",
                                                  "()Ljava/lang/String;")
        location_api_upper = result.apkinfo.upperfunc(location_api)

        sms_api = result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms",
                                             "(Ljava/lang/String; Ljava/lang/String;)I")
        sms_api_upper = result.apkinfo.upperfunc(sms_api)

        with pytest.raises(ValueError, match="Set is Null"):
            result.find_intersection(set(), set())
            result.find_intersection(set(), {1})
            result.find_intersection({1}, set())

        assert len(location_api_upper & sms_api_upper) == 3

        # When there is no intersection in first layer, it will try to enter
        # the second layer to check the intersection.

        # Send Location via SMS
        expected_result_location = {
            result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "doByte", "([B)V"),
            result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage", "()V"),
            result.apkinfo.find_method("Lcom/google/progress/AndroidClientService$2;", "run", "()V"),
        }

        assert result.find_intersection(location_api_upper, sms_api_upper) == expected_result_location

    def test_check_sequence(self, result):
        # Send Location via SMS

        location_method = result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation",
                                                     "()Ljava/lang/String;")
        sendSms_method = result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms",
                                                    "(Ljava/lang/String; Ljava/lang/String;)I")

        mutual_parent_true = result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage",
                                                        "()V")

        mutual_parent_false = result.apkinfo.find_method("Lcom/google/progress/AndroidClientService$2;", "run", "()V")

        # # Send contact via SMS

        contact_method = result.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList",
            "()Ljava/lang/String;"
        )

        assert result.check_sequence(
            mutual_parent_true,
            [location_method],
            [sendSms_method],

        ) is True

        assert result.check_sequence(
            mutual_parent_true,
            [contact_method],
            [sendSms_method],

        ) is True

        assert result.check_sequence(
            mutual_parent_false,
            [contact_method],
            [sendSms_method],
        ) is False

    def test_check_parameter(self, result):
        second_method = [result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms",
                                                    "(Ljava/lang/String; Ljava/lang/String;)I")]
        first_method = [
            result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation", "()Ljava/lang/String;")]
        mutual_parent = result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage", "()V")

        assert result.check_parameter(mutual_parent, first_method, second_method) is True
