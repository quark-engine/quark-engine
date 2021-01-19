# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import hashlib
import os
import re

from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex

from quark.Objects.bytecodeobject import BytecodeObject


class Apkinfo:
    """Information about apk based on androguard analysis"""

    __slots__ = [
        "ret_type",
        "apk",
        "dalvikvmformat",
        "analysis",
        "apk_filename",
        "apk_filepath",
    ]

    def __init__(self, apk_filepath):
        """Information about apk based on androguard analysis"""
        self.ret_type = androconf.is_android(apk_filepath)

        if self.ret_type == "APK":
            # return the APK, list of DalvikVMFormat, and Analysis objects
            self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(apk_filepath)

        if self.ret_type == "DEX":
            # return the sha256hash, DalvikVMFormat, and Analysis objects
            _, _, self.analysis = AnalyzeDex(apk_filepath)

        self.apk_filename = os.path.basename(apk_filepath)
        self.apk_filepath = apk_filepath

    def __repr__(self):
        return f"<Apkinfo-APK:{self.apk_filename}>"

    @property
    def filename(self):
        """
        Return the filename of apk.

        :return: a string of apk filename
        """
        return os.path.basename(self.apk_filepath)

    @property
    def filesize(self):
        """
        Return the file size of apk file by bytes.

        :return: a number of size bytes
        """
        return os.path.getsize(self.apk_filepath)

    @property
    def md5(self):
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
    def permissions(self):
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        if self.ret_type == "APK":
            return self.apk.get_permissions()

        if self.ret_type == "DEX":
            return []

    @functools.lru_cache()
    def find_method(self, class_name=".*", method_name=".*", descriptor=".*"):
        """
        Find method from given class_name, method_name and the descriptor.
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :param descriptor: the descriptor of the Android API
        :return: a generator of MethodClassAnalysis
        """

        regex_class_name = re.escape(class_name)
        regex_method_name = f"^{re.escape(method_name)}$"
        regex_descriptor = re.escape(descriptor)

        method_result = self.analysis.find_methods(
            classname=regex_class_name,
            methodname=regex_method_name,
            descriptor=regex_descriptor,
        )
        if list(method_result):
            (result,) = list(
                self.analysis.find_methods(
                    classname=regex_class_name,
                    methodname=regex_method_name,
                    descriptor=regex_descriptor,
                )
            )

            return result
        else:
            return None

    @functools.lru_cache()
    def upperfunc(self, method_analysis):
        """
        Return the xref from method from given method analysis instance.

        :param method_analysis: the method analysis in androguard
        :return: a set of all xref from functions
        """
        upperfunc_result = set()

        for _, call, _ in method_analysis.get_xref_from():
            # Call is the MethodAnalysis in the androguard
            # call.class_name, call.name, call.descriptor
            upperfunc_result.add(call)

        return upperfunc_result

    def get_method_bytecode(self, method_analysis):
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param method_analysis: the method analysis in androguard
        :return: a generator of all bytecode instructions
        """

        try:
            for _, ins in method_analysis.get_method().get_instructions_idx():
                bytecode_obj = None
                reg_list = []

                # count the number of the registers.
                length_operands = len(ins.get_operands())
                if length_operands == 0:
                    # No register, no parameter
                    bytecode_obj = BytecodeObject(
                        ins.get_name(),
                        None,
                        None,
                    )
                elif length_operands == 1:
                    # Only one register

                    reg_list.append(
                        f"v{ins.get_operands()[length_operands - 1][1]}",
                    )
                    bytecode_obj = BytecodeObject(
                        ins.get_name(),
                        reg_list,
                        None,
                    )
                elif length_operands >= 2:
                    # the last one is parameter, the other are registers.

                    parameter = ins.get_operands()[length_operands - 1]
                    for i in range(0, length_operands - 1):
                        reg_list.append(
                            "v" + str(ins.get_operands()[i][1]),
                        )
                    if len(parameter) == 3:
                        # method or value
                        parameter = parameter[2]
                    else:
                        # Operand.OFFSET
                        parameter = parameter[1]

                    bytecode_obj = BytecodeObject(
                        ins.get_name(),
                        reg_list,
                        parameter,
                    )

                yield bytecode_obj
        except AttributeError as error:
            # TODO Log the rule here
            pass

    def get_strings(self):

        all_strings = set()

        for string_analysis in self.analysis.get_strings():
            all_strings.add(str(string_analysis.get_orig_value()))

        return all_strings

    @functools.lru_cache()
    def construct_bytecode_instruction(self, instruction):
        """
        Construct a list of strings from the given bytecode instructions.

        :param instruction: instruction instance from androguard
        :return: a list with bytecode instructions strings
        """
        instruction_list = [instruction.get_name()]
        reg_list = []

        # count the number of the registers.
        length_operands = len(instruction.get_operands())
        if length_operands == 0:
            # No register, no parameter
            return instruction_list

        elif length_operands == 1:
            # Only one register

            reg_list.append(f"v{instruction.get_operands()[length_operands - 1][1]}")

            instruction_list.extend(reg_list)

            return instruction_list
        elif length_operands >= 2:
            # the last one is parameter, the other are registers.

            parameter = instruction.get_operands()[length_operands - 1]
            for i in range(0, length_operands - 1):
                reg_list.append(
                    "v" + str(instruction.get_operands()[i][1]),
                )
            if len(parameter) == 3:
                # method or value
                parameter = parameter[2]
            else:
                # Operand.OFFSET
                parameter = parameter[1]

            instruction_list.extend(reg_list)
            instruction_list.append(parameter)

            return instruction_list

    @functools.lru_cache()
    def get_wrapper_smali(self, method_analysis, first_method, second_method):
        """
        Return the dict of two method smali code from given method analysis object, only for self-defined
        method.
        :param method_analysis:
        :return:

        {
        "first": "invoke-virtual v5, Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;",
        "second": "invoke-virtual v3, v0, v4, Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
        }
        """

        result = {"first": None, "second": None}

        first_method_pattern = f"{first_method.class_name}->{first_method.name}{first_method.descriptor}"
        second_method_pattern = f"{second_method.class_name}->{second_method.name}{second_method.descriptor}"

        for _, ins in method_analysis.get_method().get_instructions_idx():
            if first_method_pattern in str(ins):
                result["first"] = self.construct_bytecode_instruction(ins)
            if second_method_pattern in str(ins):
                result["second"] = self.construct_bytecode_instruction(ins)

        return result
