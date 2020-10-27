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

        parent_function = list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage"))[
            0]
        expect_method_analysis = list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms"))[0]

        first_base_method = list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms"))[0]

        expected_list = [expect_method_analysis]

        wrapper = []

        result.find_previous_method(first_base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

        # Test Case 2

        wrapper = []

        second_base_method = list(result.apkinfo.find_method("Landroid/telephony/TelephonyManager", "getCellLocation"))[
            0]

        expect_method_analysis = list(result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation"))[0]

        expected_list = [expect_method_analysis]

        result.find_previous_method(second_base_method, parent_function, wrapper=wrapper)

        assert wrapper == expected_list

    def test_find_intersection(self, result):
        location_api_upper = list(result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation"))
        sms_api_upper = list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms"))
        contact_api_upper = [
            list(result.apkinfo.find_method("Lcom/google/progress/APNOperator;", "addAPN"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/ContactsCollecter;", "getPhoneNumbers"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/APNOperator;", "getAPNList"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "readSMSList"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/ContactsCollecter;", "getEmail"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/APNOperator;", "checkAPNisAvailable"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/APNOperator;", "deleteAPN"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/ContactsCollecter;", "getContactList"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/GetCallLog;", "getCallLog"))[0],
        ]

        with pytest.raises(ValueError, match="List is Null"):
            result.find_intersection([], [])
            result.find_intersection([], [1])
            result.find_intersection([1], [])

        assert len(set(location_api_upper).intersection(sms_api_upper)) == 0

        # When there is no intersection in first layer, it will try to enter
        # the second layer to check the intersection.

        # Send Location via SMS
        expected_result_location = {
            list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "doByte"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService\$2;", "run"))[0],
        }

        # Send contact via SMS
        expected_result_contact = {
            list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "doByte"))[0],
            list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage"))[0],
        }

        assert result.find_intersection(
            location_api_upper,
            sms_api_upper,
        ) == expected_result_location

        assert result.find_intersection(
            contact_api_upper,
            sms_api_upper,
        ) == expected_result_contact

    def test_check_sequence(self, result):
        # Send Location via SMS

        location_method = list(result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation"))
        sendSms_method = list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms"))

        mutual_parent_true = list(
            result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage"))[0]
        mutual_parent_false = list(
            result.apkinfo.find_method(
                "Lcom/google/progress/AndroidClientService\$2;", "run",
            ))[0]

        # # Send contact via SMS

        contact_method = list(result.apkinfo.find_method(
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList"
        ))

        assert result.check_sequence(
            mutual_parent_true,
            location_method,
            sendSms_method,
        ) == True
        assert result.check_sequence(
            mutual_parent_true,
            contact_method,
            sendSms_method,
        ) == True

        assert result.check_sequence(
            mutual_parent_false,
            contact_method,
            sendSms_method,
        ) == False

    def test_check_parameter(self, result):
        second_method = list(result.apkinfo.find_method("Lcom/google/progress/SMSHelper;", "sendSms"))
        first_method = list(result.apkinfo.find_method("Lcom/google/progress/Locate;", "getLocation"))
        mutual_parent = list(result.apkinfo.find_method("Lcom/google/progress/AndroidClientService;", "sendMessage"))[
            0]

        assert result.check_parameter(mutual_parent, first_method, second_method) == True
