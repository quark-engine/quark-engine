import pytest
import requests
from androguard.core.analysis.analysis import MethodAnalysis

from quark.Objects.apkinfo import Apkinfo

APK_SOURCE = "https://github.com/quark-engine/apk-malware-samples" \
             "/raw/master/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
APK_FILENAME = "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"


@pytest.fixture()
def apkinfo(scope="function"):
    r = requests.get(APK_SOURCE, allow_redirects=True)
    open(APK_FILENAME, "wb").write(r.content)

    apk_file = APK_FILENAME
    apkinfo = Apkinfo(apk_file)
    yield apkinfo


class TestApkinfo():

    def test_filename(self, apkinfo):
        assert apkinfo.filename == \
               "13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"

    def test_filesize(self, apkinfo):
        assert apkinfo.filesize == 266155

    def test_md5(self, apkinfo):
        assert apkinfo.md5 == "1e80ac341a665e8984f07bec7f351e18"

    def test_permissions(self, apkinfo):
        ans = [
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_BOOT_COMPLETED',
            'android.permission.WRITE_SMS',
            'android.permission.READ_SMS',
            'android.permission.INTERNET',
            'android.permission.READ_PHONE_STATE',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
        ]
        assert set(apkinfo.permissions) == set(ans)

    def test_find_method(self, apkinfo):
        result = apkinfo.find_method("Ljava/lang/reflect/Field", "setAccessible", "(Z)V")

        assert isinstance(result, MethodAnalysis)
        assert str(result.class_name) == "Ljava/lang/reflect/Field;"
        assert str(result.name) == "setAccessible"
        assert str(result.descriptor) == "(Z)V"

    def test_upperfunc(self, apkinfo):
        api = apkinfo.find_method("Ljava/lang/reflect/Field", "setAccessible", "(Z)V")

        expect_upperfunc = apkinfo.upperfunc(api)
        check_method, = expect_upperfunc
        expect_class_name = "Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;"
        expect_name = "<init>"
        expect_descriptor = "()V"

        assert str(check_method.class_name) == expect_class_name
        assert str(check_method.name) == expect_name
        assert str(check_method.descriptor) == expect_descriptor
