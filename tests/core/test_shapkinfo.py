import pytest
import requests

from quark.core.shurikenapkinfo import ShurikenImp
from quark.core.apkinfo import AndroguardImp
from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject

APK_SOURCE = (
    "https://github.com/Fare9/Shuriken-Analyzer"
    "/raw/refs/heads/main/shuriken/tests/compiled/DexParserTest.dex"
)
APK_FILENAME = "DexParserTest.dex"


@pytest.fixture(scope="function")
def apk_path():
    r = requests.get(APK_SOURCE, allow_redirects=True, timeout=10)
    file = open(APK_FILENAME, "wb")
    file.write(r.content)

    return APK_FILENAME


@pytest.fixture(
    scope="function",
    # params=((AndroguardImp),),
    params=((ShurikenImp),),
)
def apkinfo(request, apk_path):
    Apkinfo, apk_path = request.param, apk_path
    apkinfo = Apkinfo(apk_path)

    yield apkinfo


class TestApkinfo:
    def test_init_with_invalid_type(self):
        filepath = None

        with pytest.raises(TypeError):
            _ = BaseApkinfo(filepath)

    def test_init_with_non_exist_file(self):
        filepath = "PATH_TO_NON_EXIST_FILE"

        with pytest.raises(FileNotFoundError):
            _ = BaseApkinfo(filepath)

    def test_android_apis(self, apkinfo):
        api = {
            MethodObject(
                "Ljava/lang/StringBuilder;",
                "<init>",
                "()V",
            ),
        }

        assert len(apkinfo.android_apis) == 6
        assert api.issubset(apkinfo.android_apis)

    def test_custom_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "LDexParserTest;", "printMessage", "()V", access_flags=""
            ),
        }
        assert len(apkinfo.custom_methods) == 4
        assert test_custom_method.issubset(apkinfo.custom_methods)

    def test_all_methods(self, apkinfo):
        test_custom_method = {
            MethodObject(
                "LDexParserTest;", "printMessage", "()V", access_flags=""
            ),
        }

        assert len(apkinfo.all_methods) == 10
        assert test_custom_method.issubset(apkinfo.all_methods)

    @staticmethod
    @pytest.mark.parametrize(
        "test_input, expected",
        [
            (
                [
                    "LDexParserTest;",
                    "printMessage",
                    "()V",
                ],
                [
                    "LDexParserTest;",
                    "printMessage",
                    "()V",
                ],
            ),
        ],
    )
    def test_find_method(apkinfo, test_input, expected):
        result = apkinfo.find_method(
            test_input[0], test_input[1], test_input[2]
        )
        expect_method = MethodObject(
            expected[0],
            expected[1],
            expected[2],
        )

        assert isinstance(result, list)
        assert expect_method in result

    def test_upperfunc(self, apkinfo):
        api = apkinfo.find_method(
            "LDexParserTest;",
            "printMessage",
            "()V",
        )[0]

        expect_function = apkinfo.find_method(
            "LDexParserTest;",
            "main",
            "([Ljava/lang/String;)V",
        )[0]

        upper_methods = list(apkinfo.upperfunc(api))

        assert expect_function in upper_methods

    def test_lowerfunc(self, apkinfo):
        api = apkinfo.find_method(
            "LDexParserTest;",
            "printMessage",
            "()V",
        )[0]

        expect_function = apkinfo.find_method(
            "Ljava/lang/StringBuilder;",
            "<init>",
            "()V",
        )[0]
        lower_methods = list(apkinfo.lowerfunc(api))
        expected_offset = 60
        assert (expect_function, expected_offset) in lower_methods

    def test_get_method_bytecode(self, apkinfo):
        expected_bytecode_list = [
            BytecodeObject(
                "invoke-direct", ["v1"], "Ljava/lang/Object;-><init>()V"
            ),
            BytecodeObject("const/16", ["v0"], 42),
            BytecodeObject("iput", ["v0", "v1"], "LDexParserTest;->field1 I"),
            BytecodeObject("const-string", ["v0"], "Hello, Dex Parser!"),
            BytecodeObject(
                "iput-object",
                ["v0", "v1"],
                "LDexParserTest;->field2 Ljava/lang/String;",
            ),
            BytecodeObject("return-void", None, None),
        ]

        method = apkinfo.find_method(
            class_name="LDexParserTest;",
            method_name="<init>",
            descriptor="()V",
        )[0]

        bytecodes = list(apkinfo.get_method_bytecode(method))

        for expected in expected_bytecode_list:
            assert expected in bytecodes

    def test_get_strings(self, apkinfo):
        expectedValue = {
            " and ",
            " is: ",
            "Field 1: ",
            "Field 2: ",
            "Hello, Dex Parser!",
            "Sum of ",
            "This is a test message printed from DexParserTest class.",
        }
        result = apkinfo.get_strings()
        assert expectedValue == result

    def test_get_wrapper_smali(self, apkinfo):
        expectedValue = {
            "first": [
                "invoke-direct",
                "v2",
                "LDexParserTest;-><init>()V",
            ],
            "first_hex": "70 10 00 00 02 00",
            "second": [
                "invoke-direct",
                "v2",
                "LDexParserTest;->printMessage()V",
            ],
            "second_hex": "70 10 03 00 02 00",
        }

        parentMethod = apkinfo.find_method(
            class_name="LDexParserTest;",
            method_name="main",
            descriptor="([Ljava/lang/String;)V",
        )[0]

        firstAPI = apkinfo.find_method(
            class_name="LDexParserTest;",
            method_name="<init>",
            descriptor="()V",
        )[0]

        secondAPI = apkinfo.find_method(
            class_name="LDexParserTest;",
            method_name="printMessage",
            descriptor="()V",
        )[0]

        result = apkinfo.get_wrapper_smali(parentMethod, firstAPI, secondAPI)

        assert result == expectedValue

    def test_superclass_relationships_with_expected_class(self, apkinfo):
        expected_upper_class = {"Ljava/lang/Object;"}
        class_name = "LDexParserTest;"

        upper_set = apkinfo.superclass_relationships[class_name]

        assert expected_upper_class == upper_set

    def test_subclass_relationships_with_expected_class(self, apkinfo):
        expected_upper_class = {"LDexParserTest;"}
        class_name = "Ljava/lang/Object;"

        lower_set = apkinfo.subclass_relationships[class_name]

        assert expected_upper_class == lower_set
