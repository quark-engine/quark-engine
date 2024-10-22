# -*- coding: utf-8 -*-
# This file is part of Quark-Engine:
# https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import functools
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Union, Iterator

from shuriken import Dex
from shuriken.dex import hdvmmethodanalysis_t, hdvminstruction_t

from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import remove_dup_list


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
        methods = self.all_methods
        androidAPIs = set(
            filter(lambda method: method.cache.external, methods)
        )

        return androidAPIs

    @property
    def custom_methods(self) -> Set[MethodObject]:
        methods = self.all_methods
        customMethods = set(
            filter(lambda method: not method.cache.external, methods)
        )

        return customMethods

    @property
    def all_methods(self) -> Set[MethodObject]:
        methods = set()
        for i in range(self.analysis.get_number_of_classes()):
            rawClass = self.analysis.get_class_by_id(i)
            className = rawClass.class_name.decode()
            classAnalysis = self.analysis.get_analyzed_class(className)
            for j in range(classAnalysis.n_of_methods):
                methodAnalysis = classAnalysis.methods[j].contents
                method = self._convert_to_method_object(methodAnalysis)
                methods = methods.union(self.lowerfunc(method))
                methods.add(method)
        return methods

    @functools.lru_cache
    def _getMethodsClassified(self):
        """
        Parse all methods in the specified Dex and convert them into a
        dictionary. The dictionary takes their belonging classes as the keys.
        Then, it categorizes them into lists.

        :return: a dictionary taking a class name as the key and a list of
        MethodObject as the corresponding value.
        """
        methodDict = defaultdict(list)
        for method in self.all_methods:
            if method:
                methodDict[method.class_name].append(method)

        # Remove duplicates
        for class_name, method_list in methodDict.items():
            methodDict[class_name] = remove_dup_list(method_list)

        return methodDict

    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> List[MethodObject]:
        if not class_name:
            class_name = ".*"

        if class_name != ".*":
            regexClassName = re.escape(class_name)
        else:
            regexClassName = class_name

        if not method_name:
            method_name = ".*"

        if method_name != ".*":
            regexMethodName = f"^{re.escape(method_name)}$"
        else:
            regexMethodName = f"^{method_name}$"

        if not descriptor:
            descriptor = ".*"

        if descriptor != ".*":
            regexDescriptor = re.escape(descriptor)
        else:
            regexDescriptor = descriptor

        def methodFilter(method):
            return re.match(regexMethodName, method.name) and re.match(
                regexDescriptor, method.descriptor
            )

        filteredMethods = list()

        if regexClassName != ".*":
            methodDict = self._getMethodsClassified()
            filteredMethods += list(
                filter(methodFilter, methodDict[class_name])
            )
        else:
            methodDict = self._getMethodsClassified()
            for key_name in methodDict:
                filteredMethods += list(
                    filter(methodFilter, methodDict[key_name])
                )

        return filteredMethods

    @functools.lru_cache()
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        methodAnalysis = method_object.cache

        upperFuncs = set()
        for i in range(methodAnalysis.n_of_xreffrom):
            upperFuncs.add(
                self._convert_to_method_object(
                    methodAnalysis.xreffrom[i].method.contents
                )
            )

        return upperFuncs

    @functools.lru_cache()
    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        methodAnalysis = method_object.cache

        lowerFuncs = set()
        for i in range(methodAnalysis.n_of_xrefto):
            lowerFuncs.add(
                self._convert_to_method_object(
                    methodAnalysis.xrefto[i].method.contents
                )
            )

        return lowerFuncs

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Iterator[BytecodeObject]:
        """
        Inherited from baseapkinfo.py.
        Return the bytecodes of the specified method.

        :param method_object: a target method to get the corresponding
        bytecodes
        :yield: a generator of BytecodeObjects
        """
        methodAnalysis = method_object.cache
        disassembledMethod = self.analysis.get_disassembled_method(
            methodAnalysis.full_name.decode()
        )
        for i in range(disassembledMethod.n_of_instructions):
            rawBytecode = disassembledMethod.instructions[
                i
            ].disassembly.decode()
            yield self._parseSmali(rawBytecode)

    def _parseParameters(self, parameter: str) -> Union[int, float]:

        if parameter[:2] == "0x":
            try:
                parameter = int(parameter, 16)
                return parameter
            except (TypeError, ValueError):
                pass

        try:
            parameter = int(parameter, 10)
            return parameter
        except (TypeError, ValueError):
            pass
        try:
            parameter = float(parameter)
            return parameter
        except (TypeError, ValueError):
            pass

        typeTable = {
            "void": "V",
            "boolean": "Z",
            "byte": "B",
            "short": "S",
            "char": "C",
            "int": "I",
            "long": "J",
            "float": "F",
            "double": "D",
        }
        for typeName, abbreviation in typeTable.items():
            parameter = parameter.strip()
            pattern = r" ({})(\[\])*$".format(typeName)
            if re.search(pattern, parameter):
                parameter = re.sub(
                    pattern, r" {}\2".format(abbreviation), parameter
                )
                break

        parameter = re.sub(r"([^;])->", r"\1;->", parameter)

        if parameter[0] != "L":
            parameter = "L" + parameter
        return parameter

    def _parseSmali(self, smali: str) -> BytecodeObject:

        smali = smali.split("//")[0].strip()
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args = smali.split(maxsplit=1)
        parameter = None

        # extract string
        if args[-1] == '"' or args[-1] == "'":
            quoteChar = '"'
            if args[-1] == "'":
                quoteChar = "'"

            firstQuotePosition = args.find(quoteChar)
            parameter = args[firstQuotePosition:][1:-1]
            args = args[:firstQuotePosition].strip()

        argsList = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        if parameter is None:
            if argsList and not argsList[-1].startswith("v"):
                parameter = self._parseParameters(argsList.pop())

        return BytecodeObject(mnemonic, argsList, parameter)

    def get_strings(self) -> Set[str]:
        strings = set()
        for i in range(self.analysis.get_number_of_strings()):
            strings.add(self.analysis.get_string_by_id(i).decode())
        return strings

    @functools.lru_cache()
    def _construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        pass

    def _find_first_bytecode_by_calling_method(
        self, bytecodes: Iterator[BytecodeObject], target_method: MethodObject
    ) -> Optional[BytecodeObject]:
        targetMethodCall = f"{target_method.class_name}->{target_method.name}{target_method.descriptor}"

        for bytecode in bytecodes:
            if (
                bytecode.mnemonic.startswith("invoke")
                and targetMethodCall in bytecode.parameter
            ):
                return bytecode

    @functools.lru_cache()
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        bytecodes = self.get_method_bytecode(parent_method)

        first = self._find_first_bytecode_by_calling_method(
            bytecodes, first_method
        )
        second = self._find_first_bytecode_by_calling_method(
            bytecodes, second_method
        )

        return {
            "first": [
                first.mnemonic,
                " ".join(first.registers),
                first.parameter,
            ],
            "first_hex": "",  # TODO - Finish me
            "second": [
                second.mnemonic,
                " ".join(second.registers),
                second.parameter,
            ],
            "second_hex": "",  # TODO - Finish me
        }

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
            # access_flags=methodAnalysis.access_flags,
            class_name=methodAnalysis.class_name.decode(),
            name=methodAnalysis.name.decode(),
            descriptor=methodAnalysis.descriptor.decode(),
            cache=methodAnalysis,
        )
