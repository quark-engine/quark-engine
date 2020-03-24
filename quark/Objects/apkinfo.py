# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.
import os

from androguard.misc import AnalyzeAPK

from quark.Objects.bytecodeobject import BytecodeObject
from quark.utils import tools


class Apkinfo:
    """Information about apk based on androguard analysis"""

    def __init__(self, apk_filepath):
        """Information about apk based on androguard analysis"""
        # return the APK, list of DalvikVMFormat, and Analysis objects
        self.apk, self.dalvikvmformat, self.analysis = AnalyzeAPK(apk_filepath)
        self.apk_filename = os.path.basename(apk_filepath)

    def __repr__(self):
        return "<Apkinfo-APK:{}>".format(self.apk_filename)

    @property
    def permissions(self):
        """
        Return all permissions from given APK.

        :return: a list of all permissions
        """
        return self.apk.get_permissions()

    def find_method(self, class_name=".*", method_name=".*"):
        """
        Find method from given class_name and method_name,
        default is find all method.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a generator of MethodClassAnalysis
        """

        result = self.analysis.find_methods(class_name, method_name)

        if list(result):
            return self.analysis.find_methods(class_name, method_name)

        return None

    def upperfunc(self, class_name, method_name):
        """
        Return the upper level method from given class name and
        method name.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a list of all upper functions
        """

        upperfunc_result = []
        method_set = self.find_method(class_name, method_name)

        if method_set is not None:
            for method in method_set:
                for _, call, _ in method.get_xref_from():
                    # Get class name and method name:
                    # call.class_name, call.name
                    upperfunc_result.append((call.class_name, call.name))

            return tools.remove_dup_list(upperfunc_result)

        return None

    def get_method_bytecode(self, class_name, method_name):
        """
        Return the corresponding bytecode according to the
        given class name and method name.

        :param class_name: the class name of the Android API
        :param method_name: the method name of the Android API
        :return: a generator of all bytecode instructions
        """

        result = self.analysis.find_methods(class_name, method_name)

        if list(result):
            for method in self.analysis.find_methods(class_name, method_name):
                for _, ins in method.get_method().get_instructions_idx():
                    bytecode_obj = None
                    reg_list = []

                    # count the number of the registers.
                    length_operands = len(ins.get_operands())
                    if length_operands == 0:
                        # No register, no parameter
                        bytecode_obj = BytecodeObject(ins.get_name(), None, None)
                    elif length_operands == 1:
                        # Only one register

                        reg_list.append(f"v{ins.get_operands()[length_operands - 1][1]}")
                        bytecode_obj = BytecodeObject(ins.get_name(), reg_list, None)
                    elif length_operands >= 2:
                        # the last one is parameter, the other are registers.

                        parameter = ins.get_operands()[length_operands - 1]
                        for i in range(0, length_operands - 1):
                            reg_list.append(
                                "v" + str(ins.get_operands()[i][1]))
                        if len(parameter) == 3:
                            # method or value
                            parameter = parameter[2]
                        else:
                            # Operand.OFFSET
                            parameter = parameter[1]

                        bytecode_obj = BytecodeObject(ins.get_name(), reg_list, parameter)

                    yield bytecode_obj
