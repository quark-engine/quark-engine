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
from quark.utils.tools import descriptor_to_androguard_format, remove_dup_list

RizinCache = namedtuple("rizin_cache", "address dexindex is_imported")

PRIMITIVE_TYPE_MAPPING = {
    "void": "V",
    "boolean": "Z",
    "byte": "B",
    "char": "C",
    "short": "S",
    "int": "I",
    "long": "J",
    "float": "F",
    "double": "D",
    "Boolean": "Ljava/lang/Boolean;",
    "Byte": "Ljava/lang/Byte;",
    "Character": "Ljava/lang/Character;",
    "Short": "Ljava/lang/Short;",
    "Integer": "Ljava/lang/Integer;",
    "Long": "Ljava/lang/Long;",
    "Float": "Ljava/lang/Float;",
    "Double": "Ljava/lang/Double;",
    "String": "Ljava/lang/String;",
}

RIZIN_ESCAPE_CHAR_LIST = ["<", ">", "$"]


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

    def _convert_type_to_type_signature(self, raw_type: str):
        if raw_type.endswith("[]"):
            return "[" + self._convert_type_to_type_signature(raw_type[:-2])

        if raw_type.startswith("["):
            return "[" + self._convert_type_to_type_signature(raw_type[1:])

        if raw_type in PRIMITIVE_TYPE_MAPPING:
            return PRIMITIVE_TYPE_MAPPING[raw_type]

        if "." in raw_type or "_" in raw_type:
            raw_type = raw_type.replace(".", "/")
            raw_type = raw_type.replace("_", "$")
            return "L" + raw_type + ";"

        return raw_type

    @staticmethod
    def _escape_str_in_rizin_manner(raw_str: str):
        for c in RIZIN_ESCAPE_CHAR_LIST:
            raw_str = raw_str.replace(c, "_")
        return raw_str

    @functools.lru_cache
    def _get_methods_classified(self, dexindex):
        rz = self._get_rz(dexindex)

        method_json_list = rz.cmdj("isj")
        method_dict = defaultdict(list)
        for json_obj in method_json_list:
            if json_obj.get("type") not in ["FUNC", "METH"]:
                continue

            # -- Descriptor --
            full_method_name = json_obj["name"]
            raw_argument_str = next(
                re.finditer("\\(.*\\).*", full_method_name), None
            )
            if raw_argument_str is None:
                continue
            raw_argument_str = raw_argument_str.group(0)

            if raw_argument_str.endswith(")"):
                # Convert Java lauguage type to JVM type signature

                # Parse the arguments
                raw_argument_str = raw_argument_str[1:-1]
                arguments = [
                    self._convert_type_to_type_signature(arg)
                    for arg in raw_argument_str.split(", ")
                ]

                # Parse the return type
                return_type = next(
                    re.finditer(
                        "[A-Za-zL][A-Za-z0-9L/\\;[\\]$.]+ ", full_method_name
                    ),
                    None,
                )
                if return_type is None:
                    print(f"Unresolved method signature: {full_method_name}")
                    continue
                return_type = return_type.group(0).strip()

                # Convert
                raw_argument_str = (
                    "("
                    + " ".join(arguments)
                    + ")"
                    + self._convert_type_to_type_signature(return_type)
                )

            descriptor = descriptor_to_androguard_format(raw_argument_str)

            # -- Method name --
            method_name = json_obj["realname"]

            # -- Is imported --
            is_imported = json_obj["is_imported"]

            # -- Class name --
            # Test if the class name is truncated
            escaped_method_name = self._escape_str_in_rizin_manner(method_name)
            if escaped_method_name.endswith("_"):
                escaped_method_name = escaped_method_name[:-1]

            flag_name = json_obj["flagname"]

            # sym.imp.clone doesn't belong to a class
            if flag_name == "sym.imp.clone":
                method = MethodObject(
                    class_name="",
                    name="clone",
                    descriptor="()Ljava/lang/Object;",
                    cache=RizinCache(json_obj["vaddr"], dexindex, is_imported),
                )
                method_dict[""].append(method)
                continue

            if escaped_method_name not in flag_name:
                logging.warning(
                    f"The class name may be truncated: {json_obj['flagname']}"
                )

            # Drop the method name
            match = None
            for match in re.finditer("_+[A-Za-z]+", flag_name):
                pass
            if match is None:
                logging.warning(
                    f"Skip the damaged flag: {json_obj['flagname']}"
                )
                continue
            match = match.group(0)
            flag_name = flag_name[: flag_name.rfind(match)]

            # Drop the prefixes sym. and imp.
            while flag_name.startswith("sym.") or flag_name.startswith("imp."):
                flag_name = flag_name[4:]

            class_name = self._convert_type_to_type_signature(flag_name)

            # Append the method
            method = MethodObject(
                class_name=class_name,
                name=method_name,
                descriptor=descriptor,
                cache=RizinCache(json_obj["vaddr"], dexindex, is_imported),
            )
            method_dict[class_name].append(method)

        # Remove duplicates
        for class_name, method_list in method_dict.items():
            method_dict[class_name] = remove_dup_list(method_list)

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
                matched_method = self._get_method_by_address(xref["fcn_addr"])
                if not matched_method:
                    logging.debug(
                        f"Cannot identify function at {xref['fcn_addr']}."
                    )
                    continue

                upperfunc_set.add(matched_method)
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
                matched_method = self._get_method_by_address(xref["to"])
                if not matched_method:
                    logging.debug(
                        f"Cannot identify function at {xref['fcn_addr']}."
                    )
                    continue

                offset = xref["from"] - cache.address

                lowerfunc_set.add(
                    (
                        matched_method,
                        offset,
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
    def superclass_relationships(self) -> Dict[str, Set[str]]:
        hierarchy_dict = defaultdict(set)

        for dex_index in range(self._number_of_dex):

            rz = self._get_rz(dex_index)

            class_info_list = rz.cmdj("icj")
            for class_info in class_info_list:
                class_name = class_info["classname"]
                super_class = class_info["super"]

                hierarchy_dict[class_name].add(super_class)

        return hierarchy_dict

    @functools.cached_property
    def subclass_relationships(self) -> Dict[str, Set[str]]:
        hierarchy_dict = defaultdict(set)

        for dex_index in range(self._number_of_dex):

            rz = self._get_rz(dex_index)

            class_info_list = rz.cmdj("icj")
            for class_info in class_info_list:
                class_name = class_info["classname"]
                super_class = class_info["super"]

                hierarchy_dict[super_class].add(class_name)

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
        # if mnemonic.startswith("invoke"):
        #     args = args[: args.rfind(" ;")]

        args = [arg.strip() for arg in re.split("[{},]+", args) if arg]

        parameter = None
        # Remove the parameter at the last
        if args and not args[-1].startswith("v"):
            parameter = args[-1]
            args = args[:-1]

            if mnemonic.startswith("invoke"):
                parameter = re.sub(r"\.", "->", parameter, count=1)

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
