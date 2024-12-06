# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
import os
import zipfile
import tempfile
import functools
from collections import defaultdict
from os import PathLike
from typing import Dict, List, Optional, Set, Union, Iterator, Generator, Tuple

from shuriken import Dex, Apk
from shuriken.dex import (
    hdvmmethodanalysis_t,
    hdvminstruction_t,
    dvmdisassembled_method_t,
    hdvmclass_t,
)

from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject
from quark.utils.tools import descriptor_to_androguard_format


class ShurikenImp(BaseApkinfo):
    """Information about apk based on Shuriken-Analyzer analysis"""

    __slots__ = ("apk", "dalvikvmformat", "analysis", "_tmp_dir", "_manifest")

    def __init__(
        self,
        apk_filepath: Union[str, PathLike],
        tmp_dir: Union[str, PathLike] = None,
    ):
        super().__init__(apk_filepath, "shuriken")
        match self.ret_type:
            case "APK":
                self.analysis = Apk(apk_filepath, create_xrefs=True)
                self._tmp_dir = (
                    tempfile.mkdtemp() if tmp_dir is None else tmp_dir
                )
                with zipfile.ZipFile(self.apk_filepath) as apk:
                    apk.extract("AndroidManifest.xml", path=self._tmp_dir)
                    self._manifest = os.path.join(
                        self._tmp_dir, "AndroidManifest.xml"
                    )
            case "DEX":
                self.analysis = Dex(apk_filepath)
                self.analysis.disassemble_dex()
                self.analysis.create_dex_analysis(1)
                self.analysis.analyze_classes()
                self._manifest = None
            case _:
                raise ValueError("Unsupported File type.")

    @property
    def android_apis(self) -> Set[MethodObject]:
        """
        Return all Android native APIs from given APK.

        :return: a set of MethodObjects
        """
        methods = self.all_methods
        androidAPIs = set(
            filter(
                lambda method: (
                    method.is_android_api() and method.cache.is_android_api
                ),
                methods,
            )
        )

        return androidAPIs

    @property
    def custom_methods(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all custom methods declared by the sample.

        :return: a set of MethodObjects
        """
        return {
            method for method in self.all_methods if not method.cache.external
        }

    @property
    def all_methods(self) -> Set[MethodObject]:
        """
        Inherited from baseapkinfo.py.
        Return all methods including Android native APIs and custom methods
        declared in the sample.

        :return: a set of MethodObjects
        """
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
                    methods.add(
                        self.__convert_to_method_object(methodAnalysis)
                    )

            case "DEX":
                # TODO - Wait for the upstream to support getting all methods.
                for i in range(self.analysis.get_number_of_classes()):
                    rawClass = self.analysis.get_class_by_id(i)
                    className = rawClass.class_name.decode()
                    classAnalysis = self.analysis.get_analyzed_class(className)
                    for j in range(classAnalysis.n_of_methods):
                        methodAnalysis = classAnalysis.methods[j].contents
                        method = self.__convert_to_method_object(
                            methodAnalysis
                        )
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
        """
        Inherited from baseapkinfo.py.
        Find a method with the given class name, method name, and descriptor.

        :param class_name: the class name of the target method. Defaults to
        None
        :param method_name: the method name of the target method. Defaults to
        None
        :param descriptor: the descriptor of the target method. Defaults to
        None
        :return: a list of the target MethodObject
        """
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
        """
        Inherited from baseapkinfo.py.
        Find the xrefs from the specified method.

        :param method_object: a target method which the returned methods
        should call
        :return: a set of MethodObjects
        """
        methodAnalysis = method_object.cache
        upperFuncs = set()
        for i in range(methodAnalysis.n_of_xreffrom):
            upperFuncs.add(
                self.__convert_to_method_object(
                    methodAnalysis.xreffrom[i].method.contents
                )
            )

        return upperFuncs

    @functools.lru_cache()
    def lowerfunc(
        self, method_object: MethodObject
    ) -> list[Tuple[MethodObject, int]]:
        """
        Inherited from baseapkinfo.py.
        Find the xrefs to the specified method.

        :param method_object: a target method used to find what methods it
        calls
        :return: a set of tuples consisting of the called method and the
        offset of the invocation
        """
        methodAnalysis = method_object.cache

        lowerFuncs = []
        for i in range(methodAnalysis.n_of_xrefto):
            xref = methodAnalysis.xrefto[i]
            lowerFuncs.append(
                (
                    self.__convert_to_method_object(xref.method.contents),
                    xref.idx,
                )
            )

        return lowerFuncs

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Generator[BytecodeObject, None, None]:
        """
        Inherited from baseapkinfo.py.
        Return the bytecodes of the specified method.

        :param method_object: a target method to get the corresponding
        bytecodes
        :yield: a generator of BytecodeObjects
        """
        disassembledMethod = self.__getDisassembledMethod(method_object)
        if method_object.cache.external:
            return
        for i in range(disassembledMethod.n_of_instructions):
            rawSmali = disassembledMethod.instructions[i].disassembly.decode(
                errors="backslashreplace"
            )
            yield self.__parseSmali(rawSmali)

    def __parseParameters(self, parameter: str) -> Union[int, float, str]:
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

        patternToIdentifyMethodCall = r"->\w+\("
        if re.search(patternToIdentifyMethodCall, parameter):
            parameter = self.__convertMethodCallFormat(parameter)

        patternToIdentifyMemberField = r"->\w+(?!\() "
        if re.search(patternToIdentifyMemberField, parameter):
            parameter = self.__convertMemberFieldFormat(parameter)

        return parameter

    def __parseSmali(self, smali: str) -> BytecodeObject:
        """
        Parses the given smali code string into a BytecodeObject.

        :param smali: a smali code string disassembled from an instruction
        :return: a BytecodeObject
        """
        smali = smali.split("//")[0].strip()
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args = smali.split(maxsplit=1)
        parameter = None

        if args[-1] == '"' or args[-1] == "'":
            # Extract string
            quoteChar = args[-1]
            firstQuotePosition = args.find(quoteChar)
            parameter = args[firstQuotePosition:][1:-1]
            args = args[:firstQuotePosition].strip()

        argsList = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        if parameter is None and argsList and not argsList[-1].startswith("v"):
            parameter = self.__parseParameters(argsList.pop())

        return BytecodeObject(mnemonic, argsList, parameter)

    def get_strings(self) -> Set[str]:
        """
        Inherited from baseapkinfo.py.
        Return all strings in the sample.

        :return: a set of strings
        """
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

    def __findMethodCallInstruction(
        self,
        method: MethodObject,
        instructions: list[hdvminstruction_t],
        start: int = 0,
    ) -> int | None:
        targetMethodCall = (
            (
                f"{method.class_name}->{method.name}"
                f"{method.descriptor.replace(' ', '')}"
            )
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
        instructions: list[hdvminstruction_t],
        rawBytes: bytes,
        start: int = 0,
    ):
        idx = self.__findMethodCallInstruction(
            targetMethod, instructions, start
        )
        smali = self.__parseSmali(
            instructions[idx].disassembly.decode(errors="backslashreplace")
        )

        offset = sum(ins.instruction_length for ins in instructions[:idx])
        hex_bytes = rawBytes[
            offset: offset + instructions[idx].instruction_length
        ].hex(" ")

        return {
            "index": idx,
            "smali": [smali.mnemonic] + smali.registers + [smali.parameter],
            "hex": hex_bytes,
        }

    @functools.lru_cache
    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> dict[str, BytecodeObject | str]:
        """
        Inherited from baseapkinfo.py.
        Find the invocations that call two specified methods, first_method
        and second_method, respectively. Then, return a dictionary storing
        the corresponding bytecodes and hex values.

        :param parent_method: a parent method to scan
        :param first_method: the first method called by the parent method
        :param second_method: the second method called by the parent method
        :return: a dictionary storing the corresponding bytecodes and hex
        values.
        """
        disassembledMethod = self.__getDisassembledMethod(parent_method)

        numOfIns = disassembledMethod.n_of_instructions
        instructions = disassembledMethod.instructions[:numOfIns]

        method = (
            disassembledMethod.method_id.contents
        )
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
        """
        Inherited from baseapkinfo.py.
        Return a dictionary holding the inheritance relationship of classes in
        the sample. The dictionary takes a class name as the key and the
        corresponding superclass as the value.

        :return: a dictionary taking a class name as the key and the
        corresponding superclass as the value.
        """
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self.__convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self.__convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[className].add(superclassName)

        return hierarchyDict

    @property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        """
        Inherited from baseapkinfo.py.
        Return a dictionary holding the inheritance relationship of classes in
        the sample. Return a dictionary holding the inheritance relationship
        of classes in the sample. The dictionary takes a class name as the key
        and the corresponding subclasses as the value.

        :return: a dictionary taking a class name as the key and the
        corresponding subclasses as the value.
        """
        rawClasses = self.__getClasses()

        hierarchyDict = defaultdict(set)

        for rawClass in rawClasses:
            className = self.__convertClassNameFormat(
                rawClass.class_name.decode()
            )
            superclassName = self.__convertClassNameFormat(
                rawClass.super_class.decode()
            )

            hierarchyDict[superclassName].add(className)

        return hierarchyDict

    def __convert_to_method_object(
        self,
        methodAnalysis: hdvmmethodanalysis_t,
    ) -> MethodObject:
        className = self.__convertClassNameFormat(
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

    def __convertClassNameFormat(self, className: str) -> str:

        if not className.endswith(";"):
            className = "L" + className.replace(".", "/") + ";"

        return className

    def __convertMemberFieldFormat(self, memberField: str) -> str:

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
            memberField = memberField.strip()
            pattern = r" ({})(\[\])*$".format(typeName)
            if re.search(pattern, memberField):
                memberField = re.sub(
                    pattern, r" {}\2".format(abbreviation), memberField
                )
                break

        className, field = memberField.split("->")
        className = self.__convertClassNameFormat(className)
        fieldName, fieldType = field.split(" ")

        primitiveTypeChar = list(typeTable.values())
        isFieldPrimitiveType = fieldType in primitiveTypeChar

        fieldTypeArrayDimension = 0
        while fieldType.endswith("[]"):
            fieldTypeArrayDimension += 1
            fieldType = fieldType[:-2]

        isFieldPrimitiveArray = (
            fieldTypeArrayDimension and fieldType in primitiveTypeChar
        )

        if not isFieldPrimitiveType or not isFieldPrimitiveArray:
            fieldType = self.__convertClassNameFormat(fieldType)

        fieldType = "[" * fieldTypeArrayDimension + fieldType

        return f"{className}->{fieldName} {fieldType}"

    def __convertMethodCallFormat(self, methodCall: str) -> str:
        if methodCall.count(";") < 3:
            return methodCall

        endWithSemiColon = methodCall.endswith(";")
        if endWithSemiColon:
            methodCall = methodCall[:-1]

        fragment = methodCall.split(";")
        className = fragment[0]
        returnType = fragment[-1]
        fragment = fragment[1:-1]
        parsedMethodCall = (
            className + ";" + "; ".join(fragment) + ";" + returnType
        )
        if endWithSemiColon:
            parsedMethodCall += ";"
        return parsedMethodCall
