from RuleObject import RuleObject
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex
import operator
from utils.tools import *


class x_rule:
    def __init__(self, apk):
        """
        apk: apk filename
        """
        self.a, self.d, self.dx = AnalyzeAPK(apk)

        # Create Class, Method, String and Field
        # crossreferences for all classes in the Analysis.
        self.dx.create_xref()

        self.pre_method0 = []
        self.pre_method1 = []

    @property
    def permissions(self):
        """
        rtype: list
        """
        return self.a.get_permissions()

    def find_method(self, class_name=".*", method_name=".*"):
        """
        Find method from given class_name and method_name,
        default is return all.

        rtype: Iterator[MethodAnalysis]
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

    def find_intersection(self, list1, list2, depth=1):
        """
        Find the list1 ∩ list2.

        list1 & list2 are  list withing tuple, like
        [("class_name","method_name"),...]
        """
        # Check the list is not null
        if len(list1) > 0 and len(list2) > 0:

            # Limit up to three layers of the recursions.
            if depth == 3:
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

    def check_sequence(self, same_method, first_func, second_func):
        """
        Check if the first function appeared before the second function.
        """
        method_set = self.find_method(same_method[0], same_method[1])
        seq_table = []

        if method_set is not None:
            for md in method_set:
                for _, call, number in md.get_xref_to():

                    if (
                        call.class_name == first_func[0] and call.name == first_func[1]
                    ) or (
                        call.class_name == second_func[0]
                        and call.name == second_func[1]
                    ):
                        seq_table.append((call.name, number))

            # sorting based on the value of the number
            if len(seq_table) < 2:
                print("Not Found sequence in " + method_name)
                return False
            seq_table.sort(key=operator.itemgetter(1))

            idx = 0
            length = len(seq_table)
            first_firstfunc_val = None
            first_secondfunc_val = None
            while idx < length:
                if seq_table[idx][0] == first_func[1]:
                    first_firstfunc_val = idx
                    break
                idx += 1
            while length > 0:
                if seq_table[length - 1][0] == second_func[1]:
                    first_secondfunc_val = length - 1
                    break
                length -= 1

            if first_secondfunc_val > first_firstfunc_val:
                print("Found sequence in :" + repr(same_method))
                return True
            else:
                return False

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

                    # print("[O]共同出現於:\n" + repr(same))

                    pre_0 = self.pre_method0.pop()[0]
                    pre_1 = self.pre_method1.pop()[0]

                    for same_method in same:

                        if self.check_sequence(same_method, pre_0, pre_1):
                            print("4==> [O]")


data = x_rule("14d9f1a92dd984d6040cc41ed06e273e.apk")

rule_checker = RuleObject("sendLocation.json")

data.run(rule_checker)
