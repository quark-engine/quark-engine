from Objects.RuleObject import RuleObject
from Objects.BytecodeObject import BytecodeObject
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex
import operator
from utils.tools import *
from pyeval import PyEval
from parser import parse

MAX_SEARCH_LAYER = 3


class XRule:
    def __init__(self, apk):

        self.a, self.d, self.dx = AnalyzeAPK(apk)

        # Create Class, Method, String and Field
        # crossreferences for all classes in the Analysis.
        # self.dx.create_xref()

        self.pre_method0 = []
        self.pre_method1 = []

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

        if (result is not None) and len(list(result)) > 0:
            return self.dx.find_methods(class_name, method_name)

        else:
            # Method Not Found
            return None

    def upperFunc(self, class_name, method_name):
        """
        Find the upper level method from given class name and
        method name.

        rtype: list
        """

        result = []
        method_set = self.find_method(class_name, method_name)

        if method_set is not None:
            for md in method_set:
                for _, call, _ in md.get_xref_from():
                    # Get class name and method name:
                    # call.class_name, call.name
                    result.append((call.class_name, call.name))

            return remove_dup_list(result)
        else:
            return None

    def get_method_bytecode(self, class_name, method_name):

        result = self.dx.find_methods(class_name, method_name)

        if result is not None:
            for m in self.dx.find_methods(class_name, method_name):
                for idx, ins in m.get_method().get_instructions_idx():
                    bytecode_obj = None

                    # count the number of the registers.
                    length_operands = len(ins.get_operands())
                    if length_operands == 0:
                        # No register, no parm
                        bytecode_obj = BytecodeObject(ins.get_name(), None, None)
                    elif length_operands == 1:
                        # Only one register
                        bytecode_obj = BytecodeObject(
                            ins.get_name(),
                            ins.get_operands()[length_operands - 1][1],
                            None,
                        )
                    elif length_operands >= 2:
                        # the last one is parm, the other are registers.
                        reg_list = []
                        parameter = ins.get_operands()[length_operands - 1]
                        for i in range(0, length_operands - 1):
                            reg_list.append(ins.get_operands()[i][1])
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
            raise ValueError("Method Not Found")

    def find_intersection(self, list1, list2, depth=1):
        """
        Find the list1 ∩ list2.

        list1 & list2 are  list withing tuple, for example,
        [("class_name","method_name"),...]

        :rtype:
        """
        # Check both lists are not null
        if len(list1) > 0 and len(list2) > 0:

            # Limit up to three layers of the recursions.
            if depth == MAX_SEARCH_LAYER:
                return None
            # find ∩
            result = set(list1).intersection(list2)
            if len(result) > 0:

                return result
            else:
                # Not found same method usage, try to find the next layer.

                next_list1 = []
                next_list2 = []
                for item in list1:
                    next_list1 = self.upperFunc(item[0], item[1])
                for item in list2:
                    next_list2 = self.upperFunc(item[0], item[1])
                # Append first layer into next layer
                for pre_list in list1:
                    next_list1.append(pre_list)
                for pre_list in list2:
                    next_list2.append(pre_list)

                depth += 1

                # To find the same method, push the previous two
                # methods into the stack here. Once it found there
                # is same method, pop the previous method from stack.
                self.pre_method0.append(list1)
                self.pre_method1.append(list2)

                return self.find_intersection(next_list1, next_list2, depth)
        else:
            raise ValueError("List is Null")

    def check_sequence(self, same_method, f_func, s_func):
        """
        Check if the first function appeared before the second function.
        same_method: the tuple with (class_name, method_name)
        f_func: the first show up function, which is (class_name, method_name)
        s_func: the tuple with (class_name, method_name)
        """
        method_set = self.find_method(same_method[0], same_method[1])
        seq_table = []

        if method_set is not None:
            for md in method_set:
                for _, call, number in md.get_xref_to():

                    if (call.class_name == f_func[0] and call.name == f_func[1]) or (
                        call.class_name == s_func[0] and call.name == s_func[1]
                    ):
                        seq_table.append((call.name, number))

            # sorting based on the value of the number
            if len(seq_table) < 2:
                print("Not Found sequence in " + same_method)
                return False
            seq_table.sort(key=operator.itemgetter(1))

            idx = 0
            length = len(seq_table)
            f_func_val = None
            s_func_val = None
            while idx < length:
                if seq_table[idx][0] == f_func[1]:
                    f_func_val = idx
                    break
                idx += 1
            while length > 0:
                if seq_table[length - 1][0] == s_func[1]:
                    s_func_val = length - 1
                    break
                length -= 1

            if s_func_val > f_func_val:
                print("Found sequence in :" + repr(same_method))
                return True
            else:
                return False

    def check_parameter(self, fist_method_name, second_method_name):
        """
        check the usage of the same parameter between
        two method.
        """

        pyeval = PyEval()
        # Check if there is an operation of the same register
        state = False

        # TODO replace it to get_output(),get_name()
        for bytecode in parse("ag_file/target.ag"):
            if bytecode[0] in pyeval.eval.keys():
                pyeval.eval[bytecode[0]](bytecode)

        for table in pyeval.show_table():
            for val_obj in table:
                matchers = [fist_method_name, second_method_name]
                matching = [
                    s for s in val_obj.called_by_func if all(xs in s for xs in matchers)
                ]
                if len(matching) > 0:
                    state = True
                    break
        return state

    def run(self, rule_obj):
        """
        Run five levels check to get the y_score.
        """
        # Level 1
        if set(rule_obj.x1_permission).issubset(set(self.permissions)):
            print("1==> [O]")

        # Level 2
        test_md0 = rule_obj.x2n3n4_comb[0]["method"]
        test_cls0 = rule_obj.x2n3n4_comb[0]["class"]
        if self.find_method(test_cls0, test_md0) is not None:
            print("2==> [O]")

            # Level 3
            test_md1 = rule_checker.x2n3n4_comb[1]["method"]
            test_cls1 = rule_checker.x2n3n4_comb[1]["class"]
            if self.find_method(test_cls1, test_md1) is not None:
                print("3==> [O]")

                # Level 4
                # [('class_a','method_a'),('class_b','method_b')]
                # Looking for the first layer of the upperfunction
                upperfunc0 = self.upperFunc(test_cls0, test_md0)
                upperfunc1 = self.upperFunc(test_cls1, test_md1)

                same = self.find_intersection(upperfunc0, upperfunc1)
                if same is not None:

                    pre_0 = self.pre_method0.pop()[0]
                    pre_1 = self.pre_method1.pop()[0]

                    for same_method in same:

                        if self.check_sequence(same_method, pre_0, pre_1):
                            print("4==> [O]")

                            if self.check_parameter(str(pre_0[1]), str(pre_1[1])):
                                print("5==> [O]")


data = XRule("sample/14d9f1a92dd984d6040cc41ed06e273e.apk")

rule_checker = RuleObject("rules/sendLocation.json")

data.run(rule_checker)


for obj in data.get_method_bytecode(
    "Lcom/google/progress/AndroidClientService;", "sendMessage"
):
    print("------------------")
    print(obj.mnemonic)
    print(obj.registers)
    print(obj.parameter)
    print("------------------")

