import os
import zipfile

import pytest
import requests

from quark.core.apkinfo import AndroguardImp
from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.rzapkinfo import RizinImp
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject

APK_SOURCE = (
    "https://github.com/quark-engine/apk-samples"
    "/raw/master/malware-samples/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
)
APK_FILENAME = "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"


@pytest.fixture(scope="function")
def apk_path():
    r = requests.get(APK_SOURCE, allow_redirects=True)
    file = open(APK_FILENAME, "wb")
    file.write(r.content)

    return APK_FILENAME


@pytest.fixture(
    scope="function",
    params=((AndroguardImp), (RizinImp)),
)
def apkinfo(request, apk_path):
    Apkinfo, apk_path = request.param, apk_path
    apkinfo = Apkinfo(apk_path)

    yield apkinfo


@pytest.fixture(scope="function")
def dex_file():
    APK_SOURCE = (
        "https://github.com/quark-engine/apk-samples" "/raw/master/malware-samples/Ahmyth.apk"
    )
    APK_NAME = "Ahmyth.apk"
    DEX_NAME = "classes.dex"

    r = requests.get(APK_SOURCE, allow_redirects=True)
    with open(APK_NAME, "wb") as file:
        file.write(r.content)

    with zipfile.ZipFile(APK_NAME, "r") as zip:
        zip.extract(DEX_NAME)

    yield DEX_NAME

    os.remove(DEX_NAME)
    os.remove(APK_NAME)


class TestApkinfo:
    def test_init_with_invalid_type(self):
        filepath = None

        with pytest.raises(TypeError):
            _ = BaseApkinfo(filepath)

    def test_init_with_non_exist_file(self):
        filepath = "PATH_TO_NON_EXIST_FILE"

        with pytest.raises(FileNotFoundError):
            _ = BaseApkinfo(filepath)

    def test_init_with_apk(self, apk_path):
        apkinfo = BaseApkinfo(apk_path)

        assert apkinfo.ret_type == "APK"

    def test_init_with_dex(self, dex_file):
        apkinfo = BaseApkinfo(dex_file)

        assert apkinfo.ret_type == "DEX"

    def test_filename(self, apkinfo):
        assert apkinfo.filename == "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"

    def test_filesize(self, apkinfo):
        assert apkinfo.filesize == 266155

    def test_md5(self, apkinfo):
        assert apkinfo.md5 == "1e80ac341a665e8984f07bec7f351e18"

    def test_permissions(self, apkinfo):
        ans = [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.WRITE_SMS",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
            "android.permission.READ_PHONE_STATE",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
        ]
        assert set(apkinfo.permissions) == set(ans)

    @staticmethod
    def test_application(apkinfo):
        application = apkinfo.application
        label = str(application.get(
            "{http://schemas.android.com/apk/res/android}label"
        ))
        assert label == "@7F050001" or label == "2131034113"

    @staticmethod
    def test_activities(apkinfo):
        activities = apkinfo.activities

        assert len(activities) == 1
        assert (
            activities[0].get(
                "{http://schemas.android.com/apk/res/android}name"
            )
            == "com.example.google.service.MainActivity"
        )

    def test_android_apis(self, apkinfo):
        api = {
            MethodObject(
                "Landroid/telephony/SmsMessage;",
                "getDisplayOriginatingAddress",
                "()Ljava/lang/String;",
            ),
            MethodObject(
                "Ljava/io/File;",
                "mkdir",
                "()Z",
            ),
        }

        if apkinfo.core_library == "androguard":
            assert len(apkinfo.android_apis) == 1270
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.android_apis) == 1269
        assert api.issubset(apkinfo.android_apis)

    def test_custom_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getPhoneContacts",
                "()V",
            ),
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getSIMContacts",
                "()V",
            ),
        }
        if apkinfo.core_library == "androguard":
            assert len(apkinfo.custom_methods) == 3999
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.custom_methods) == 3990
        assert test_custom_method.issubset(apkinfo.custom_methods)

    def test_all_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getPhoneContacts",
                "()V",
            ),
            MethodObject(
                "Lcom/example/google/service/ContactsHelper;",
                "getSIMContacts",
                "()V",
            ),
        }

        if apkinfo.core_library == "androguard":
            assert len(apkinfo.all_methods) == 5452
        elif apkinfo.core_library == "rizin":
            assert len(apkinfo.all_methods) == 5260

        assert test_custom_method.issubset(apkinfo.all_methods)

    def test_find_method(self, apkinfo):
        result1 = apkinfo.find_method(
            "Ljava/lang/reflect/Field;", "setAccessible", "(Z)V"
        )

        assert isinstance(result1[0], MethodObject)
        assert str(result1[0].class_name) == "Ljava/lang/reflect/Field;"
        assert str(result1[0].name) == "setAccessible"
        assert str(result1[0].descriptor) == "(Z)V"

        expect_method = MethodObject(
            "Landroid/support/v4/media/TransportMediatorJellybeanMR2$3;",
            "onReceive",
            "(Landroid/content/Context; Landroid/content/Intent;)V",
            "public",
        )
        result2 = apkinfo.find_method(
            method_name="onReceive",
            descriptor="(Landroid/content/Context; Landroid/content/Intent;)V",
        )
        result3 = apkinfo.find_method(
            class_name="",
            method_name="onReceive",
            descriptor="(Landroid/content/Context; Landroid/content/Intent;)V",
        )
        result4 = apkinfo.find_method(
            class_name="",
            method_name="onReceive",
            descriptor="",
        )

        assert isinstance(result2, list)
        assert len(result2) == 5
        assert expect_method in result2

        assert isinstance(result3, list)
        assert len(result3) == 5
        assert expect_method in result3

        assert isinstance(result4, list)
        assert len(result4) == 5
        assert expect_method in result4

        assert result2 == result3
        assert result3 == result4

    def test_upperfunc(self, apkinfo):
        api = apkinfo.find_method(
            "Lcom/example/google/service/ContactsHelper;",
            "<init>",
            "(Landroid/content/Context;)V",
        )[0]

        expect_function = apkinfo.find_method(
            "Lcom/example/google/service/SMSReceiver;",
            "isContact",
            "(Ljava/lang/String;)Ljava/lang/Boolean;",
        )[0]

        upper_methods = list(apkinfo.upperfunc(api))

        assert expect_function in upper_methods

    def test_lowerfunc(self, apkinfo):
        method = apkinfo.find_method(
            "Lcom/example/google/service/WebServiceCalling;",
            "Send",
            "(Landroid/os/Handler; Ljava/lang/String;)V",
        )[0]

        expect_method = MethodObject(
            "Ljava/lang/StringBuilder;",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        )
        expect_offset = 42

        upper_methods = apkinfo.lowerfunc(method)

        assert (expect_method, expect_offset) in upper_methods

    def test_get_method_bytecode(self, apkinfo):
        expected_bytecode_list = [
            BytecodeObject(
                "iput-object",
                ["v5", "v8"],
                (
                    "Landroid/support/v4/app/FragmentManagerImpl;"
                    "->mTmpActions [Ljava/lang/Runnable;"
                ),
            ),
            BytecodeObject(
                "invoke-direct",
                ["v5", "v6"],
                (
                    "Ljava/lang/IllegalStateException;"
                    "-><init>(Ljava/lang/String;)V"
                ),
            ),
            BytecodeObject("array-length", ["v5", "v5"], None),
            BytecodeObject(
                "invoke-static",
                [],
                "Landroid/os/Looper;->myLooper()Landroid/os/Looper;",
            ),
            BytecodeObject("return", ["v0"], None),
            BytecodeObject("const/4", ["v3"], 0),
            BytecodeObject("add-int/lit8", ["v2", "v2"], 1),
        ]

        method = apkinfo.find_method(
            class_name="Landroid/support/v4/app/FragmentManagerImpl;",
            method_name="execPendingActions",
            descriptor="()Z",
        )[0]

        bytecodes = list(apkinfo.get_method_bytecode(method))

        for expected in expected_bytecode_list:
            assert expected in bytecodes

    def test_lowerfunc(self, apkinfo):
        method = apkinfo.find_method(
            "Lcom/example/google/service/SMSReceiver;",
            "isContact",
            "(Ljava/lang/String;)Ljava/lang/Boolean;",
        )[0]

        expect_method = apkinfo.find_method(
            "Lcom/example/google/service/ContactsHelper;",
            "<init>",
            "(Landroid/content/Context;)V",
        )[0]
        expect_offset = 10

        upper_methods = apkinfo.lowerfunc(method)

        assert (expect_method, expect_offset) in upper_methods

    def test_superclass_relationships_with_expected_class(self, apkinfo):
        expected_upper_class = {"Lcom/example/google/service/HttpHelper;"}
        class_name = "Lcom/example/google/service/WebServiceCalling;"

        upper_set = apkinfo.superclass_relationships[class_name]

        assert expected_upper_class == upper_set
