# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
from os import PathLike
from typing import Dict, List, Optional, Set, Union

from shuriken import Dex
from shuriken.dex import hdvmmethodanalysis_t

from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject


class ShurikenImp(BaseApkinfo):
    """Information about apk based on Shuriken-Analyzer analysis"""

    __slots__ = ("apk", "dalvikvmformat", "analysis")

    def __init__(self, apk_filepath: Union[str, PathLike]):
        super().__init__(apk_filepath, "shuriken")

        if self.ret_type == "APK":
            pass
        elif self.ret_type == "DEX":
            self.analysis = Dex(apk_filepath)
            self.analysis.disassemble_dex()
            self.analysis.create_dex_analysis(1)
            self.analysis.analyze_classes()
        else:
            raise ValueError("Unsupported File type.")

    @property
    def permissions(self) -> List[str]:
        pass

    @property
    def application(self) -> XMLElement:
        """Get the application element from the manifest file.

        :return: an application element
        """
        pass

    @property
    def activities(self) -> List[XMLElement]:
        pass

    @property
    def receivers(self) -> List[XMLElement]:
        """
        Return all receivers from the given APK.

        :return: a list of all receivers
        """
        pass

    @property
    def android_apis(self) -> Set[MethodObject]:
        methods = set()
        for i in range(self.analysis.get_number_of_classes()):
            rawClass = self.analysis.get_class_by_id(i)
            className = rawClass.class_name.decode()
            classAnalysis = self.analysis.get_analyzed_class(className)
            for j in range(classAnalysis.n_of_methods):
                methodAnalysis = classAnalysis.methods[i].contents
                if methodAnalysis.is_android_api:
                    methods.add(
                        self._convert_to_method_object(methodAnalysis)
                    )
        return methods

    @property
    def custom_methods(self) -> Set[MethodObject]:
        methods = set()
        for i in range(self.analysis.get_number_of_classes()):
            rawClass = self.analysis.get_class_by_id(i)
            className = rawClass.class_name.decode()
            classAnalysis = self.analysis.get_analyzed_class(className)
            for j in range(classAnalysis.n_of_methods):
                methodAnalysis = classAnalysis.methods[i].contents
                if methodAnalysis.external:
                    methods.add(
                        self._convert_to_method_object(methodAnalysis)
                    )
        return methods

    @property
    def all_methods(self) -> Set[MethodObject]:
        methods = set()
        for i in range(self.analysis.get_number_of_classes()):
            rawClass = self.analysis.get_class_by_id(i)
            className = rawClass.class_name.decode()
            classAnalysis = self.analysis.get_analyzed_class(className)
            for j in range(classAnalysis.n_of_methods):
                methodAnalysis = classAnalysis.methods[i].contents
                methods.add(
                    self._convert_to_method_object(methodAnalysis)
                )
        return methods

    @functools.lru_cache()
    def find_method(
            self,
            class_name: Optional[str] = ".*",
            method_name: Optional[str] = ".*",
            descriptor: Optional[str] = ".*",
    ) -> List[MethodObject]:
        pass

    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        pass

    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        pass

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Set[MethodObject]:
            pass

    def get_strings(self) -> str:
        pass

    @functools.lru_cache()
    def _construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        pass

    @functools.lru_cache()
    def get_wrapper_smali(
            self,
            parent_method: MethodObject,
            first_method: MethodObject,
            second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        pass

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        pass

    @staticmethod
    def _convert_to_method_object(
        methodAnalysis: hdvmmethodanalysis_t,
    ) -> MethodObject:
        return MethodObject(
            #access_flags=methodAnalysis.access_flags,
            class_name=methodAnalysis.class_name.decode(),
            name=methodAnalysis.name.decode(),
            descriptor=methodAnalysis.descriptor.decode(),
            cache=methodAnalysis,
        )