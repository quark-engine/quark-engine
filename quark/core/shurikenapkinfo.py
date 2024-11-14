# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import functools
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Union, Iterator, Tuple

from shuriken import Dex, Apk
from shuriken.dex import (
    hdvmmethodanalysis_t,
    hdvminstruction_t,
    dvmdisassembled_method_t,
    hdvmclass_t,
)

from quark.core.axmlreader import AxmlReader
from quark.core.interface.baseapkinfo import BaseApkinfo, XMLElement
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format


class ShurikenImp(BaseApkinfo):
    """Information about apk based on Shuriken-Analyzer analysis"""

    __slots__ = ("apk", "dalvikvmformat", "analysis")

    def __init__(self, apk_filepath: Union[str, PathLike]):
        super().__init__(apk_filepath, "shuriken")

        match self.ret_type:
            case "APK":
                self.analysis = Apk(apk_filepath, create_xrefs=True)
            case "DEX":
                self.analysis = Dex(apk_filepath)
                self.analysis.disassemble_dex()
                self.analysis.create_dex_analysis(1)
                self.analysis.analyze_classes()
            case _:
                raise ValueError("Unsupported File type.")

    @property
    def permissions(self) -> List[str]:
        """
        Inherited from baseapkinfo.py.
        Return the permissions used by the sample.

        :return: a list of permissions.
        """
        with AxmlReader(self._manifest) as axml:
            permission_list = set()

            for tag in axml:
                label = tag.get("Name")
                if label and axml.getString(label) == "uses-permission":
                    attrs = axml.getAttributes(tag)

                    if attrs:
                        permission = axml.getString(attrs[0].value)
                        permission_list.add(permission)

            return list(permission_list)

    @property
    def application(self) -> XMLElement:
        """Get the application element from the manifest file.

        :return: an application element
        """
        with AxmlReader(self._manifest) as axml:
            root = axml.getXmlTree()

            return root.find("application")

    @property
    def activities(self) -> List[XMLElement]:
        """
        Return all activity from given APK.

        :return: a list of all activities
        """
        with AxmlReader(self._manifest) as axml:
            root = axml.getXmlTree()

            return root.findall("application/activity")

    @property
    def receivers(self) -> List[XMLElement]:
        """
        Return all receivers from the given APK.

        :return: a list of all receivers
        """
        with AxmlReader(self._manifest) as axml:
            root = axml.getXmlTree()

            return root.findall("application/receiver")

    @property
    def android_apis(self) -> Set[MethodObject]:
        methods = self.all_methods
        androidAPIs = set(
            filter(lambda method: method.cache.is_android_api, methods)
        )

        return androidAPIs

    @property
    def custom_methods(self) -> Set[MethodObject]:
        return {
            method for method in self.all_methods if not method.cache.external
        }

    @property
    def all_methods(self) -> Set[MethodObject]:
        methods = set()

        match self.ret_type:
            case "APK":
                numOfMethod = (
                    self.analysis.get_number_of_methodanalysis_objects()
                )
                for i in range(numOfMethod):
                    methodAnalysis = self.analysis.get_analyzed_method_by_idx(
                        i
                    )
                    methods.add(self._convert_to_method_object(methodAnalysis))

            case "DEX":
                # TODO - Wait for the upstream to add an API to get all methods.
                for i in range(self.analysis.get_number_of_classes()):
                    rawClass = self.analysis.get_class_by_id(i)
                    className = rawClass.class_name.decode()
                    classAnalysis = self.analysis.get_analyzed_class(className)
                    for j in range(classAnalysis.n_of_methods):
                        methodAnalysis = classAnalysis.methods[j].contents
                        method = self._convert_to_method_object(methodAnalysis)
                        lowerMethodInfo = self.lowerfunc(method)
                        lowerMethods = [info[0] for info in lowerMethodInfo]
                        methods = methods.union(set(lowerMethods))
                        methods.add(method)
            case _:
                raise ValueError("Unsupported File type.")

        return methods

    @functools.lru_cache()
    def find_method(
        self,
        class_name: Optional[str] = None,
        method_name: Optional[str] = None,
        descriptor: Optional[str] = None,
    ) -> List[MethodObject]:
        methods = self.all_methods
        if class_name:
            methods = (m for m in methods if class_name == m.class_name)

        if method_name:
            methods = (m for m in methods if method_name == m.name)

        if descriptor:
            methods = (m for m in methods if descriptor == m.descriptor)

        return list(methods)

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
    def lowerfunc(
        self, method_object: MethodObject
    ) -> list[Tuple[MethodObject, int]]:
        methodAnalysis = method_object.cache

        lowerFuncs = []
        for i in range(methodAnalysis.n_of_xrefto):
            xref = methodAnalysis.xrefto[i]
            lowerFuncs.append(
                (
                    self._convert_to_method_object(xref.method.contents),
                    xref.idx,
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
        disassembledMethod = self.__getDisassembledMethod(method_object)

        for i in range(disassembledMethod.n_of_instructions):
            rawBytecode = disassembledMethod.instructions[
                i
            ].disassembly.decode(errors="backslashreplace")
            yield self._parseSmali(rawBytecode)

    def _parseParameters(self, parameter: str) -> Union[int, float, str]:

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

        patternToIdentifyMemberField = r"->\w+(?!\(\)) "
        if re.search(patternToIdentifyMemberField, parameter):
            parameter = self._convertMemberFieldFormat(parameter)

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
        quoteChar = args[-1]
        if quoteChar == '"' or quoteChar == "'":

            firstQuotePosition = args.find(quoteChar)
            parameter = args[firstQuotePosition:][1:-1]
            args = args[:firstQuotePosition].strip()

        argsList = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        if parameter is None:
            if argsList and not argsList[-1].startswith("v"):
                parameter = self._parseParameters(argsList.pop())

        return BytecodeObject(mnemonic, argsList, parameter)

    def get_strings(self) -> Set[str]:
        match self.ret_type:
            case "APK":
                dexList = (
                    self.analysis.get_dex_file_by_index(i)
                    for i in range(self.analysis.get_number_of_dex_files())
                )

                rawString = (
                    self.analysis.get_string_by_id_from_dex(dex, i)
                    for dex in dexList
                    for i in range(
                        self.analysis.get_number_of_strings_from_dex(dex)
                    )
                )

            case "DEX":
                rawString = (
                    self.analysis.get_string_by_id(i).decode(
                        errors="backslashreplace"
                    )
                    for i in range(self.analysis.get_number_of_strings())
                )

            case _:
                raise ValueError("Unsupported File type.")

        return {s for s in rawString if s}

    @functools.lru_cache()
    def _construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        pass

    def __findMethodCallInstruction(
        self,
        method: MethodObject,
        instructions: List[hdvminstruction_t],
        start=0,
    ) -> Optional[int]:
        targetMethodCall = (
            f"{method.class_name}->{method.name}{method.descriptor}"
        )

        for idx in range(start, len(instructions)):
            bytecodeStr = instructions[idx].disassembly.decode(
                errors="backslashreplace"
            )
            if (
                bytecodeStr.startswith("invoke")
                and targetMethodCall in bytecodeStr
            ):
                return idx

    def __getDisassembledMethod(
        self, method: MethodObject
    ) -> dvmdisassembled_method_t:
        methodAnalysis = method.cache

        match self.ret_type:
            case "DEX":
                return self.analysis.get_disassembled_method(
                    methodAnalysis.full_name.decode()
                )
            case "APK":
                return self.analysis.get_disassembled_method_from_apk(
                    methodAnalysis.full_name.decode()
                )
            case _:
                raise ValueError("Unsupported File type.")

    def __extractMethodCallDetails(
        self,
        targetMethod: MethodObject,
        instructions: List[hdvminstruction_t],
        rawBytes: bytes,
        start: int = 0,
    ):
        idx = self.__findMethodCallInstruction(
            targetMethod, instructions, start
        )
        smali = self._parseSmali(
            instructions[idx].disassembly.decode(errors="backslashreplace")
        )

        offset = sum(ins.instruction_length for ins in instructions[:idx])
        hex_bytes = rawBytes[
            offset : offset + instructions[idx].instruction_length
        ].hex(" ")

        return {
            "index": idx,
            "smali": [
                smali.mnemonic,
                " ".join(smali.registers),
                smali.parameter,
            ],
            "hex": hex_bytes,
        }

    @functools.lru_cache()
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:

        disassembledMethod = self.__getDisassembledMethod(parent_method)

        numOfIns = disassembledMethod.n_of_instructions
        instructions = disassembledMethod.instructions[:numOfIns]

        method = disassembledMethod.method_id.contents # TODO - Throw ValueError due to a bug from the upstream. Wait for the upstream to fix it.
        rawBytes = bytes(method.code[: method.code_size])

        firstResult = self.__extractMethodCallDetails(
            first_method, instructions, rawBytes
        )
        secondResult = self.__extractMethodCallDetails(
            second_method,
            instructions,
            rawBytes,
            start=firstResult["index"] + 1,
        )

        return {
            "first": firstResult["smali"],
            "first_hex": firstResult["hex"],
            "second": secondResult["smali"],
            "second_hex": secondResult["hex"],
        }

    def __getClasses(self) -> Iterator[hdvmclass_t]:
        match self.ret_type:
            case "APK":
                dexList = (
                    self.analysis.get_dex_file_by_index(i)
                    for i in range(self.analysis.get_number_of_dex_files())
                )

                rawClasses = (
                    self.analysis.get_hdvmclass_from_dex_by_index(dex, i)
                    for dex in dexList
                    for i in range(
                        self.analysis.get_number_of_classes_for_dex_file(dex)
                    )
                )

            case "DEX":
                rawClasses = (
                    self.analysis.get_class_by_id(i)
                    for i in range(self.analysis.get_number_of_classes())
                )

            case _:
                raise ValueError("Unsupported File type.")
        return rawClasses

    @property
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self._convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self._convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[className].add(superclassName)

        return hierarchyDict

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self._convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self._convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[superclassName].add(className)

        return hierarchyDict

    def _convert_to_method_object(
        self,
        methodAnalysis: hdvmmethodanalysis_t,
    ) -> MethodObject:
        className = self._convertClassNameFormat(
            methodAnalysis.class_name.decode()
        )

        return MethodObject(
            # access_flags=methodAnalysis.access_flags,
            class_name=className,
            name=methodAnalysis.name.decode(),
            descriptor=descriptor_to_androguard_format(
                methodAnalysis.descriptor.decode()
            ),
            cache=methodAnalysis,
        )

    def _convertClassNameFormat(self, className: str) -> str:

        if not className.endswith(";"):
            className = "L" + className.replace(".", "/") + ";"

        return className

    def _convertMemberFieldFormat(self, memberField: str) -> str:

        className, field = memberField.split("->")
        fieldName, fieldType = field.split(" ")

        className = self._convertClassNameFormat(className)

        primitiveTypeChar = ["V", "Z", "B", "S", "C", "I", "J", "F", "D"]

        isFieldPrimitiveType = fieldType in primitiveTypeChar
        isFieldPrimitiveArray = fieldType.split("[")[-1] in primitiveTypeChar
        if not isFieldPrimitiveType or not isFieldPrimitiveArray:
            fieldType = self._convertClassNameFormat(fieldType)

        return f"{className}->{fieldName} {fieldType}"
