import pytest

from quark.Objects.xrule import XRule


@pytest.fixture()
def xrule(scope="function"):
    apk_file = "quark/sample/14d9f1a92dd984d6040cc41ed06e273e.apk"
    xrule = XRule(apk_file)
    yield xrule


class TestXRule():

    def test_find_previous_method(self, xrule):
        base_method = ("Lcom/google/progress/SMSHelper;", "sendSms")
        top_method = (
            "Lcom/google/progress/AndroidClientService;",
            "sendMessage")
        expected_list = [("Lcom/google/progress/SMSHelper;", "sendSms")]

        test_list = []

        xrule.find_previous_method(base_method, top_method, test_list)

        assert test_list == expected_list

    def test_find_intersection(self, xrule):
        location_api_upper = [("Lcom/google/progress/Locate;", "getLocation")]
        sms_api_upper = [("Lcom/google/progress/SMSHelper;", "sendSms")]
        contact_api_upper = [("Lcom/google/progress/APNOperator;", "addAPN"),
                             ("Lcom/google/progress/ContactsCollecter;",
                              "getPhoneNumbers"),
                             ("Lcom/google/progress/APNOperator;", "getAPNList"),
                             ("Lcom/google/progress/SMSHelper;", "readSMSList"),
                             ("Lcom/google/progress/ContactsCollecter;", "getEmail"),
                             ("Lcom/google/progress/APNOperator;",
                              "checkAPNisAvailable"),
                             ("Lcom/google/progress/APNOperator;, deleteAPN"),
                             ("Lcom/google/progress/ContactsCollecter;",
                              "getContactList"),
                             ("Lcom/google/progress/GetCallLog;", "getCallLog")]

        with pytest.raises(ValueError, match="List is Null"):
            xrule.find_intersection([], [])
            xrule.find_intersection([], [1])
            xrule.find_intersection([1], [])

        assert len(set(location_api_upper).intersection(sms_api_upper)) == 0

        # When there is no intersection in first layer, it will try to enter
        # the second layer to check the intersection.

        # Send Location via SMS
        expected_result_location = {("Lcom/google/progress/AndroidClientService;", "doByte"),
                                    ("Lcom/google/progress/AndroidClientService;",
                                     "sendMessage"),
                                    ("Lcom/google/progress/AndroidClientService$2;", "run")}

        # Send contact via SMS
        expected_result_contact = {("Lcom/google/progress/AndroidClientService;", "doByte"),
                                   ("Lcom/google/progress/AndroidClientService;", "sendMessage")}

        assert xrule.find_intersection(
            location_api_upper,
            sms_api_upper) == expected_result_location

        assert xrule.find_intersection(
            contact_api_upper,
            sms_api_upper) == expected_result_contact

    def test_check_sequence(self, xrule):
        # Send Location via SMS

        location_api = ("Lcom/google/progress/Locate;", "getLocation")
        sendSms_api = ("Lcom/google/progress/SMSHelper;", "sendSms")

        common_method_yes = (
            "Lcom/google/progress/AndroidClientService;",
            "sendMessage")
        common_method_no = (
            "Lcom/google/progress/AndroidClientService$2;", "run")

        # # Send contact via SMS

        contact_api = (
            "Lcom/google/progress/ContactsCollecter;",
            "getContactList")
        sendSms_api = ("Lcom/google/progress/SMSHelper;", "sendSms")

        assert xrule.check_sequence(
            common_method_yes,
            location_api,
            sendSms_api) == True
        assert xrule.check_sequence(
            common_method_yes,
            contact_api,
            sendSms_api) == True
        assert xrule.check_sequence(
            common_method_no,
            location_api,
            sendSms_api) == False
        assert xrule.check_sequence(
            common_method_no,
            contact_api,
            sendSms_api) == False

    def test_check_parameter(self, xrule):
        first_method_name = "getLocation"
        second_method_name = "sendSms"

        common_method_yes = (
            "Lcom/google/progress/AndroidClientService;",
            "sendMessage")

        assert xrule.check_parameter(
            common_method_yes,
            first_method_name,
            second_method_name) == True
