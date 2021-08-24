# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import logging
import os.path
import re
import tempfile
import zipfile
from collections import defaultdict, namedtuple
from os import PathLike
from typing import Dict, Generator, List, Optional, Set, Union

import rzpipe

from quark.core.axmlreader import AxmlReader
from quark.core.interface.baseapkinfo import BaseApkinfo
from quark.core.struct.bytecodeobject import BytecodeObject
from quark.core.struct.methodobject import MethodObject

RizinCache = namedtuple("rizin_cache", "address dexindex is_imported")


class RizinImp(BaseApkinfo):
    def __init__(
        self,
        apk_filepath: Union[str, PathLike],
        tmp_dir: Union[str, PathLike] = None,
    ):
        super().__init__(apk_filepath, "rizin")

        if self.ret_type == "DEX":
            self._tmp_dir = None
            self._dex_list = [apk_filepath]

        elif self.ret_type == "APK":
            self._tmp_dir = tempfile.mkdtemp() if tmp_dir is None else tmp_dir

            with zipfile.ZipFile(self.apk_filepath) as apk:
                apk.extract("AndroidManifest.xml", path=self._tmp_dir)

                self._manifest = os.path.join(self._tmp_dir, "AndroidManifest.xml")

                dex_files = [
                    file
                    for file in apk.namelist()
                    if file.startswith("classes") and file.endswith(".dex")
                ]

                for dex in dex_files:
                    apk.extract(dex, path=self._tmp_dir)

                self._dex_list = [os.path.join(self._tmp_dir, dex) for dex in dex_files]

        else:
            raise ValueError("Unsupported File type.")

        self._number_of_dex = len(self._dex_list)

    @functools.lru_cache
    def _get_rz(self, index):
        rz = rzpipe.open(self._dex_list[index])
        rz.cmd("aa")
        return rz

    @functools.lru_cache
    def _get_methods_classified(self, dexindex):
        rz = self._get_rz(dexindex)

        method_json_list = rz.cmdj("isj")
        method_dict = defaultdict(list)
        for json_obj in method_json_list:
            if json_obj.get("type") not in ["FUNC", "METH"]:
                continue

            full_name = json_obj["realname"]
            class_name, method_descriptor = full_name.split(".method.", maxsplit=1)
            class_name = class_name + ";"

            l_index = method_descriptor.index("(")
            r_index = method_descriptor.index(")")
            methodname = method_descriptor[:l_index]
            argument_string = method_descriptor[l_index:r_index]
            argument_string = (
                "("
                + " ".join(re.findall(r"L.+?;|[ZBCSIJFD]|\[", argument_string))
                + ")"
            )

            argument_string = re.sub(r"\[ ", "[", argument_string)

            return_value = method_descriptor[method_descriptor.index(")") + 1 :]
            descriptor = argument_string + return_value

            is_imported = json_obj["is_imported"]

            method = MethodObject(
                class_name=class_name,
                name=methodname,
                descriptor=descriptor,
                cache=RizinCache(json_obj["vaddr"], dexindex, is_imported),
            )
            method_dict[class_name].append(method)

        return method_dict

    @functools.cached_property
    def permissions(self) -> List[str]:
        axml = AxmlReader(self._manifest)
        permission_list = set()

        for tag in axml:
            label = tag.get("Name")
            if label and axml.get_string(label) == "uses-permission":
                attrs = axml.get_attributes(tag)

                if attrs:
                    permission = axml.get_string(attrs[0]["Value"])
                    permission_list.add(permission)

        return permission_list

    @property
    def android_apis(self) -> Set[MethodObject]:
        return {
            method
            for method in self.all_methods
            if method.is_android_api() and method.cache.is_imported
        }

    @property
    def custom_methods(self) -> Set[MethodObject]:
        return {method for method in self.all_methods if not method.cache.is_imported}

    @functools.cached_property
    def all_methods(self) -> Set[MethodObject]:
        method_set = set()
        for dex_index in range(self._number_of_dex):
            for method_list in self._get_methods_classified(dex_index).values():
                method_set.update(method_list)

        return method_set

    def find_method(
        self,
        class_name: Optional[str] = ".*",
        method_name: Optional[str] = ".*",
        descriptor: Optional[str] = ".*",
    ) -> MethodObject:
        def method_filter(method):
            return (not method_name or method_name == method.name) and (
                not descriptor or descriptor == method.descriptor
            )

        dex_list = range(self._number_of_dex)

        for dex_index in dex_list:
            method_dict = self._get_methods_classified(dex_index)
            filtered_methods = filter(method_filter, method_dict[class_name])
            try:
                return next(filtered_methods)
            except StopIteration:
                continue

    @functools.lru_cache
    def upperfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        cache = method_object.cache

        r2 = self._get_rz(cache.dexindex)

        xrefs = r2.cmdj(f"axtj @ {cache.address}")

        upperfunc_set = set()
        for xref in xrefs:
            if xref["type"] != "CALL":
                continue

            if "fcn_addr" in xref:
                upperfunc_set.add(self._get_method_by_address(xref["fcn_addr"]))
            else:
                logging.debug(
                    f"Key from was not found at searching"
                    f" upper methods for {method_object}."
                )

        return upperfunc_set

    @functools.lru_cache
    def lowerfunc(self, method_object: MethodObject) -> Set[MethodObject]:
        cache = method_object.cache

        r2 = self._get_rz(cache.dexindex)

        xrefs = r2.cmdj(f"axffj @ {cache.address}")

        if not xrefs:
            return set()

        lowerfunc_set = set()
        for xref in xrefs:
            if xref["type"] != "CALL":
                continue

            if "to" in xref:
                lowerfunc_set.add(
                    (
                        self._get_method_by_address(xref["to"]),
                        xref["from"] - cache.address,
                    )
                )
            else:
                logging.debug(
                    f"Key from was not found at searching"
                    f" upper methods for {method_object}."
                )

        return lowerfunc_set

    def get_method_bytecode(
        self, method_object: MethodObject
    ) -> Generator[BytecodeObject, None, None]:
        cache = method_object.cache

        if not cache.is_imported:

            rz = self._get_rz(cache.dexindex)

            instruct_flow = rz.cmdj(f"pdfj @ {cache.address}")["ops"]

            if instruct_flow:
                for ins in instruct_flow:
                    yield self._parse_smali(ins["disasm"])

    def get_strings(self) -> Set[str]:
        strings = set()
        for dex_index in range(self._number_of_dex):
            rz = self._get_rz(dex_index)

            string_detail_list = rz.cmdj("izzj")
            strings.update(
                [string_detail["string"] for string_detail in string_detail_list]
            )

        return strings

    def get_wrapper_smali(
        self,
        parent_method: MethodObject,
        first_method: MethodObject,
        second_method: MethodObject,
    ) -> Dict[str, Union[BytecodeObject, str]]:
        def convert_bytecode_to_list(bytecode):
            return [bytecode.mnemonic] + bytecode.registers + [bytecode.parameter]

        cache = parent_method.cache

        result = {
            "first": None,
            "first_hex": None,
            "second": None,
            "second_hex": None,
        }

        search_pattern = "{class_name}.{name}{descriptor}"
        first_method_pattern = search_pattern.format(
            class_name=first_method.class_name[:-1],
            name=first_method.name,
            descriptor=first_method.descriptor,
        )
        second_method_pattern = search_pattern.format(
            class_name=second_method.class_name[:-1],
            name=second_method.name,
            descriptor=second_method.descriptor,
        )

        if cache.is_imported:
            return {}

        rz = self._get_rz(cache.dexindex)

        instruction_flow = rz.cmdj(f"pdfj @ {cache.address}")["ops"]

        if instruction_flow:
            for ins in instruction_flow:
                if ins["disasm"].startswith("invoke"):
                    if ";" in ins["disasm"]:
                        index = ins["disasm"].rindex(";")
                        instrcution_string = ins["disasm"][:index]

                    if first_method_pattern in instrcution_string:
                        result["first"] = convert_bytecode_to_list(
                            self._parse_smali(instrcution_string)
                        )
                        result["first_hex"] = " ".join(
                            map(
                                lambda r: r.group(0),
                                re.finditer(r"\w{2}", ins["bytes"]),
                            )
                        )
                    if second_method_pattern in instrcution_string:
                        result["second"] = convert_bytecode_to_list(
                            self._parse_smali(instrcution_string)
                        )
                        result["second_hex"] = " ".join(
                            map(
                                lambda r: r.group(0),
                                re.finditer(r"\w{2}", ins["bytes"]),
                            )
                        )

        return result

    @functools.cached_property
    def class_hierarchy(self) -> Dict[str, Set[str]]:
        hierarchy_dict = defaultdict(set)

        for dex_index in range(self._number_of_dex):

            rz = self._get_rz(dex_index)

            hierarchy_graph = rz.cmd("icg").split("\n")

            for element in hierarchy_graph:
                if element.startswith("age"):
                    element_part = element.split()
                    for index, class_name in enumerate(element_part):
                        if not class_name.endswith(";"):
                            element_part[index] = class_name + ";"

                    for subclass in element_part[2:]:
                        hierarchy_dict[subclass].add(element_part[1])

        return hierarchy_dict

    def _get_method_by_address(self, address: int) -> MethodObject:
        if address < 0:
            return None

        for method in self.all_methods:
            if method.cache.address == address:
                return method

    @staticmethod
    def _parse_smali(smali: str) -> BytecodeObject:
        if smali == "":
            raise ValueError("Argument cannot be empty.")

        if " " not in smali:
            return BytecodeObject(smali, None, None)

        mnemonic, args = smali.split(maxsplit=1)  # Split into twe parts

        # invoke-kind instruction may left method index at the last
        if mnemonic.startswith("invoke"):
            args = args[: args.rfind(" ;")]

        args = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        parameter = None
        # Remove the parameter at the last
        if args and not args[-1].startswith("v"):
            parameter = args[-1]
            args = args[:-1]

            if mnemonic.startswith("invoke"):
                parameter = re.sub(r"\.", ";->", parameter, count=1)

        register_list = []
        # Ranged registers
        if len(args) == 1 and (":" in args[0] or ".." in args[0]):
            register_list = args[0]
            register_list = [
                int(reg[1:]) for reg in re.split("[:.]+", register_list) if reg
            ]

            if ".." in args[0]:
                register_list = range(register_list[0], register_list[1] + 1)

        # Simple registers
        elif len(args) != 0:
            try:
                register_list = [int(arg[1:]) for arg in args]
            except ValueError:
                raise ValueError(f"Cannot parse bytecode. Unknown smali {smali}.")

        register_list = [f"v{index}" for index in register_list]

        return BytecodeObject(mnemonic, register_list, parameter)
