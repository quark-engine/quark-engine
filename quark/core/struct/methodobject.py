from dataclasses import dataclass, field


@dataclass(unsafe_hash=True)
class MethodObject(object):
    """
    Information about a method in a dex file.
    """

    class_name: str
    name: str
    descriptor: str
    access_flags: str = field(compare=False, default="")
    cache: object = field(compare=False, default=None, repr=False)

    @property
    def full_name(self) -> str:
        return self.__str__()

    def is_android_api(self) -> bool:
        # Packages found at https://developer.android.com/reference/packages
        api_list = [
            "Landroid/",
            "Lcom/google/android/",
            "Ldalvik/",
            "Ljava/",
            "Ljavax/",
            "Ljunit/",
            "Lorg/apache/",
            "Lorg/json/",
            "Lorg/w3c/",
            "Lorg/xml/",
            "Lorg/xmlpull/",
        ]

        return any(self.class_name.startswith(prefix) for prefix in api_list)

    def __str__(self) -> str:
        return f"{self.class_name} {self.name} {self.descriptor}"
