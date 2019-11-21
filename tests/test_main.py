
import pytest
from androguard.core.analysis.analysis import MethodAnalysis

from quark.main import XRule


@pytest.fixture()
def xrule_obj(scope="fuction"):
    apk_file = "quark/sample/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
    xrule_obj = XRule(apk_file)
    yield xrule_obj


class TestXRule():

    def test_permissions(self, xrule_obj):
        ans = [
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_BOOT_COMPLETED',
            'android.permission.WRITE_SMS',
            'android.permission.READ_SMS',
            'android.permission.INTERNET',
            'android.permission.READ_PHONE_STATE',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS'
        ]
        assert set(xrule_obj.permissions) == set(ans)

    def test_find_method(self, xrule_obj):
        result = list(xrule_obj.find_method("Ljava/lang/reflect/Field"))
        assert len(result) == 2
        assert isinstance(result[0], MethodAnalysis)

    def test_upperFunc(self, xrule_obj):
        result = xrule_obj.upperFunc("Ljava/lang/reflect/Field",
                                     "setAccessible")
        expect_func = "Landroid/support/v4/widget/SlidingPaneLayout$"\
                      "SlidingPanelLayoutImplJB;"
        assert expect_func in result[0]

