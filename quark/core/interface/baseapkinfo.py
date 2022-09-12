# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import hashlib
import os.path
from abc import abstractmethod
from os import PathLike
from typing import Dict, List, Optional, Set, Union
from xml.etree.ElementTree import Element as XMLElement  # nosec B405

from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject


class BaseApkinfo:

    __slots__ = ["ret_type", "apk_filename", "apk_filepath", "core_library"]

    def __init__(self, apk_filepath: Union[str, PathLike], core_library: str = "None"):
        with open(apk_filepath, "rb") as file:
            raw = file.read()
            self.ret_type = self._check_file_signature(raw)

        self.apk_filename = os.path.basename(apk_filepath)
        self.apk_filepath = apk_filepath
        self.core_library = core_library

    def __repr__(self) -> str:
        return f"<Apkinfo-APK:{self.apk_filename}, Imp:{self.core_library}>"

    @property
    def filename(self) -> str:
        """
        Return the filename of apk.

        :return: a string of apk filename
        """
        return os.path.basename(self.apk_filepath)

    @property
    def filesize(self) -> int:
        """
        Return the file size of apk file by bytes.

        :return: a number of size bytes
        """
        return os.path.getsize(self.apk_filepath)

    @property
    def md5(self) -> str:
        """
        Return the md5 checksum of the apk file.

        :return: a string of md5 checksum of the apk file
        """
        md5 = hashlib.md5()
        with open(self.apk_filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    @property
    @abstractmethod
    def permissions(self) -> List[str]:
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        pass

    @property
    @abstractmethod
    def activities(self) -> List[XMLElement]:
        """
        Return all activity from given APK.

        :return: a list of all activities
        """
        pass

    @property
    @abstractmethod
    def android_apis(self) -> Set[MethodObject]:
        """
        Return all Android native APIs from given APK.

        :return: a set of all Android native APIs MethodObject
        """
        pass

    @property
    @abstractmethod
    def custom_methods(self) -> Set[MethodObject]:
        """
        Return all custom methods from given APK.

        :return: a set of all custom methods MethodObject
        """
        pass

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Return all methods including Android native API and custom methods from given APK.

        :return: a set of all method MethodObject
        """
        pass

    @abstractmethod
    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> MethodObject:
        """
        Find method from given class_name, method_name and the descriptor.
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :param descriptor: the descriptor of the Android API
        :return: a generator of MethodObject
        """
        pass

    @abstractmethod
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        pass

    @abstractmethod
    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the xref from method from given MethodObject instance.

        :param method_object: the MethodObject instance
        :return: a set of all xref from functions
        """
        pass

    @abstractmethod
    def get_method_bytecode(self, method_object: MethodObject) -> Set[MethodObject]:
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param method_object: the MethodObject instance
        :return: a generator of all bytecode instructions
        """
        pass

    @abstractmethod
    def get_strings(self) -> str:
        pass

    @abstractmethod
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        """
        Return the dict of two method smali code from given MethodObject instance, only for self-defined
        method.
        :param method_analysis:
        :return:

        {
        "first": "invoke-virtual v5, Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;",
        "second": "invoke-virtual v3, v0, v4, Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
        }
        """
        pass

    @property
    @abstractmethod
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @property
    def get_subclasses(self, class_name) -> Set[str]:
        pass

    @staticmethod
    def _check_file_signature(raw: bytes) -> Optional[str]:
        if raw[0:3] == b"dex":
            return "DEX"
        elif raw[0:2] == b"PK":
            return "APK"
        elif raw[0:4] in [b"\x03\x00\x08\x00", b"\x00\x00\x08\x00"]:
            return "AXML"
        else:
            return None
