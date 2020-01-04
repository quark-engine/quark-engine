import os

from androguard.misc import AnalyzeAPK

from quark.Objects.BytecodeObject import BytecodeObject
from quark.utils import tools


class Apkinfo:

    def __init__(self, apk_filepath):
        self.a, self.d, self.dx = AnalyzeAPK(apk_filepath)

        # Create Class, Method, String and Field
        # crossreferences for all classes in the Analysis.
        # self.dx.create_xref()
        self.apk_filename = os.path.basename(apk_filepath)

    def __repr__(self):
        return "<Apkinfo-APK:{}>".format(self.apk_filename)

    @property
    def permissions(self):
        """
        :returns: A list of permissions
        :rtype: list
        """
        return self.a.get_permissions()

    def find_method(self, class_name=".*", method_name=".*"):
        """
        Find method from given class_name and method_name,
        default is find all.

        :returns: an generator of MethodClassAnalysis
        :rtype: generator
        """

        result = self.dx.find_methods(class_name, method_name)

        if len(list(result)) > 0:
            return self.dx.find_methods(class_name, method_name)

        else:
            # Method Not Found
            return None

    def upperfunc(self, class_name, method_name):
        """
        Return the upper level method from given class name and
        method name.
        :param class_name:
        :param method_name:
        :return: list
        """

        result = []
        method_set = self.find_method(class_name, method_name)

        if method_set is not None:
            for md in method_set:
                for _, call, _ in md.get_xref_from():
                    # Get class name and method name:
                    # call.class_name, call.name
                    result.append((call.class_name, call.name))

            return tools.remove_dup_list(result)
        else:
            return None

    def get_method_bytecode(self, class_name, method_name):
        """
        Return the corresponding bytecode according to the
        given class name and method name.
        :param class_name:
        :param method_name:
        :return: generator
        """

        result = self.dx.find_methods(class_name, method_name)

        if len(list(result)) > 0:
            for m in self.dx.find_methods(class_name, method_name):
                for idx, ins in m.get_method().get_instructions_idx():
                    bytecode_obj = None
                    reg_list = []

                    # count the number of the registers.
                    length_operands = len(ins.get_operands())
                    if length_operands == 0:
                        # No register, no parm
                        bytecode_obj = BytecodeObject(ins.get_name(), None, None)
                    elif length_operands == 1:
                        # Only one register

                        reg_list.append(
                            "v" + str(ins.get_operands()[length_operands - 1][1])
                        )
                        bytecode_obj = BytecodeObject(ins.get_name(), reg_list, None, )
                    elif length_operands >= 2:
                        # the last one is parm, the other are registers.

                        parameter = ins.get_operands()[length_operands - 1]
                        for i in range(0, length_operands - 1):
                            reg_list.append("v" + str(ins.get_operands()[i][1]))
                        if len(parameter) == 3:
                            # method or value
                            parameter = parameter[2]
                        else:
                            # Operand.OFFSET
                            parameter = parameter[1]

                        bytecode_obj = BytecodeObject(
                            ins.get_name(), reg_list, parameter,
                        )

                    yield bytecode_obj
        else:
            return None
            # TODO add logging
