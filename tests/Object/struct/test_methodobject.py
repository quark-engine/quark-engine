from quark.core.struct.methodobject import MethodObject


class TestMethodObject:
    def test_full_name(self):
        method = MethodObject(
            class_name="ClassName;", name="Method", descriptor="(Descriptor)"
        )

        full_name = method.full_name

        assert full_name == "ClassName; Method (Descriptor)"

    def test_compare_with_different_access_flags(self):
        method_1 = MethodObject(
            class_name="Ljava/lang/Object;",
            name="clone",
            descriptor="()Ljava/lang/Object;",
            access_flags="public",
        )

        method_2 = MethodObject(
            class_name=method_1.class_name,
            name=method_1.name,
            descriptor=method_1.descriptor,
            access_flags="protected",
        )

        assert method_1 == method_2

    def test_compare_with_different_caches(self):
        method_1 = MethodObject(
            class_name="Ljava/lang/Object;",
            name="clone",
            descriptor="()Ljava/lang/Object;",
            cache=("Cache Type A"),
        )

        method_2 = MethodObject(
            class_name=method_1.class_name,
            name=method_1.name,
            descriptor=method_1.descriptor,
            cache={"Cache Type B"},
        )

        assert method_1 == method_2

    def test_is_android_api_with_api(self):
        method = MethodObject(
            class_name="Ljava/lang/Object;",
            name="clone",
            descriptor="()Ljava/lang/Object;",
        )

        assert method.is_android_api() is True

    def test_is_android_api_with_custom_method(self):
        method = MethodObject(
            "Lcom/example/google/service/ContactsHelper;",
            "getPhoneContacts",
            "()V",
        )

        assert method.is_android_api() is False
