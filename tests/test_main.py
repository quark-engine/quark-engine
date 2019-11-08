
import unittest
from androguard.core.analysis.analysis import MethodAnalysis

from quark.main import XRule


class TestXRule(unittest.TestCase):

    def setUp(self):
        apk_file = "quark/sample/13667fe3b0ad496a0cd157f34b7e0c991d72a4db.apk"
        self.xrule_obj = XRule(apk_file)

    def test_permissions(self):
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

        self.assertEqual(set(self.xrule_obj.permissions), set(ans))

    def test_find_method(self):
        result = list(self.xrule_obj.find_method("Ljava/lang/reflect/Field"))
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], MethodAnalysis)

    def test_upperFunc(self):
        result = self.xrule_obj.upperFunc("Ljava/lang/reflect/Field", "setAccessible")
        self.assertIn("Landroid/support/v4/widget/SlidingPaneLayout$SlidingPanelLayoutImplJB;", result[0])


if __name__ == '__main__':
    unittest.main()
