import os
import zipfile

import pytest
import requests
from androguard.core.analysis.analysis import MethodAnalysis
from quark.Objects.apkinfo import Apkinfo

APK_SOURCE = (
    "https://github.com/quark-engine/apk-malware-samples"
    "/raw/master/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
)
APK_FILENAME = "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"


@pytest.fixture(scope="function")
def apk_path():
    r = requests.get(APK_SOURCE, allow_redirects=True)
    file = open(APK_FILENAME, "wb")
    file.write(r.content)

    return APK_FILENAME


@pytest.fixture(scope="function")
def apkinfo(apk_path):
    apkinfo = Apkinfo(apk_path)

    yield apkinfo


@pytest.fixture(scope="function")
def dex_file():
    APK_SOURCE = (
        "https://github.com/quark-engine/apk-malware-samples/raw/master/Ahmyth.apk"
    )
    APK_NAME = "Ahmyth.apk"
    DEX_NAME = "classes.dex"

    r = requests.get(APK_SOURCE, allow_redirects=True)
    file = open(APK_NAME, "wb")
    file.write(r.content)
    file.close()

    with zipfile.ZipFile(APK_NAME, "r") as zip:
        zip.extract(DEX_NAME)

    yield DEX_NAME

    os.remove(DEX_NAME)
    os.remove(APK_NAME)


class TestApkinfo:
    def test_init_with_invalid_type(self):
        filepath = None

        with pytest.raises(TypeError):
            _ = Apkinfo(filepath)

    def test_init_with_non_exist_file(self):
        filepath = "PATH_TO_NON_EXIST_FILE"

        with pytest.raises(FileNotFoundError):
            _ = Apkinfo(filepath)

    def test_init_with_apk(self, apk_path):
        apkinfo = Apkinfo(apk_path)

        assert apkinfo.ret_type == "APK"

    def test_init_with_dex(self, dex_file):
        apkinfo = Apkinfo(dex_file)

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

    def test_android_apis(self, apkinfo):
        api = {
            apkinfo.find_method(
                class_name="Landroid/telephony/SmsMessage;",
                method_name="getDisplayOriginatingAddress",
                descriptor="()Ljava/lang/String;",
            ),
            apkinfo.find_method(
                class_name="Ljava/io/File;",
                method_name="mkdir",
                descriptor="()Z",
            ),
        }

        assert len(apkinfo.android_apis) == 1270
        assert api.issubset(apkinfo.android_apis)

    def test_custom_methods(self, apkinfo):
        test_custom_method = {
            apkinfo.find_method(
                class_name="Lcom/example/google/service/ContactsHelper;",
                method_name="getPhoneContacts",
                descriptor="()V",
            ),
            apkinfo.find_method(
                class_name="Lcom/example/google/service/ContactsHelper;",
                method_name="getSIMContacts",
                descriptor="()V",
            ),
        }
        assert len(apkinfo.custom_methods) == 3999
        assert test_custom_method.issubset(apkinfo.custom_methods)

    def test_all_methods(self, apkinfo):
        test_custom_method = {
            apkinfo.find_method(
                class_name="Lcom/example/google/service/ContactsHelper;",
                method_name="getPhoneContacts",
                descriptor="()V",
            ),
            apkinfo.find_method(
                class_name="Lcom/example/google/service/ContactsHelper;",
                method_name="getSIMContacts",
                descriptor="()V",
            ),
        }
        assert len(apkinfo.all_methods) == 5452
        assert test_custom_method.issubset(apkinfo.all_methods)

    def test_find_method(self, apkinfo):
        result = apkinfo.find_method(
            "Ljava/lang/reflect/Field", "setAccessible", "(Z)V"
        )

        assert isinstance(result, MethodAnalysis)
        assert str(result.class_name) == "Ljava/lang/reflect/Field;"
        assert str(result.name) == "setAccessible"
        assert str(result.descriptor) == "(Z)V"

    def test_upperfunc(self, apkinfo):
        api = apkinfo.find_method("Ljava/lang/reflect/Field", "setAccessible", "(Z)V")

        expect_upperfunc = apkinfo.upperfunc(api)
        (check_method,) = expect_upperfunc
        expect_class_name = (
            "Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;"
        )
        expect_name = "<init>"
        expect_descriptor = "()V"

        assert str(check_method.class_name) == expect_class_name
        assert str(check_method.name) == expect_name
        assert str(check_method.descriptor) == expect_descriptor

    def test_lowerfunc(self, apkinfo):
        method = apkinfo.find_method(
            "Lcom/example/google/service/WebServiceCalling;",
            "Send",
            "(Landroid/os/Handler; Ljava/lang/String;)V",
        )

        expect_method = apkinfo.find_method(
            "Ljava/lang/StringBuilder;",
            "append",
            "(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        )
        expect_offset = 42

        upper_methods = apkinfo.lowerfunc(method)

        assert (expect_method, expect_offset) in upper_methods
