# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.
import copy
import operator

from prettytable import PrettyTable

from quark.Evaluator.pyeval import PyEval
from quark.Objects.apkinfo import Apkinfo
from quark.utils.colors import (
    red,
    bold,
    yellow,
    green
)

MAX_SEARCH_LAYER = 3
CHECK_LIST = "".join(["\t[" + u"\u2713" + "]"])


class XRule:
    """XRule is used to test quark's five-stage theory"""

    def __init__(self, apk):
        """

        :param apk: the filename of the apk.
        """

        self.apkinfo = Apkinfo(apk)

        self.pre_method0 = []
        self.pre_method1 = []

        self.same_sequence_show_up = []
        self.same_operation = []

        # Pretty Table Output
        self.tb = PrettyTable()
        self.tb.field_names = ["Rule", "Confidence", "Score", "Weight"]
        self.tb.align = "l"

        # Sum of the each weight
        self.weight_sum = 0
        # Sum of the each rule
        self.score_sum = 0

        self.level_2_reuslt = []

    def find_previous_method(self, base_method, top_method, pre_method_list, visited_methods=None):
        """
        Find the previous method based on base method before top method.
        This will append the method into pre_method_list.

        :param base_method: the base function which needs to be searched.
        :param top_method: the top-level function which calls the basic function.
        :param pre_method_list: list is used to track each function.
        :param visited_methods: set with tested method.
        :return: None
        """
        if visited_methods is None:
            visited_methods = set()

        class_name, method_name = base_method
        method_set = self.apkinfo.upperfunc(class_name, method_name)
        visited_methods.add(base_method)

        if method_set is not None:

            if top_method in method_set:
                pre_method_list.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(
                        item, top_method, pre_method_list, visited_methods)

    def find_intersection(self, list1, list2, depth=1):
        """
        Find the list1 ∩ list2. list1 & list2 are list within tuple, for example,
        [("class_name","method_name"),...]

        :param list1: first list that contains each method.
        :param list2: second list that contains each method.
        :param depth: maximum number of recursive search functions.
        :return: a set of list1 ∩ list2 or None.
        """
        # Check both lists are not null
        if list1 and list2:

            # find ∩
            result = set(list1).intersection(list2)
            if result:

                return result
            else:
                # Not found same method usage, try to find the next layer.
                depth += 1
                if depth > MAX_SEARCH_LAYER:
                    return None

                # Append first layer into next layer.
                next_list1 = copy.deepcopy(list1)
                next_list2 = copy.deepcopy(list2)

                # Extend the upper function into next layer.
                for item in list1:
                    if self.apkinfo.upperfunc(item[0], item[1]) is not None:
                        next_list1.extend(
                            self.apkinfo.upperfunc(
                                item[0], item[1]))
                for item in list2:
                    if self.apkinfo.upperfunc(item[0], item[1]) is not None:
                        next_list2.extend(
                            self.apkinfo.upperfunc(
                                item[0], item[1]))

                return self.find_intersection(next_list1, next_list2, depth)
        else:
            raise ValueError("List is Null")

    def check_sequence(self, same_method, first_func, second_func):
        """
        Check if the first function appeared before the second function.

        :param same_method: function that call the first function and second functions at the same time.
        :param first_func: the first show up function, which is (class_name, method_name)
        :param second_func: the second show up function, which is (class_name, method_name)
        :return: True or False
        """
        same_class_name, same_method_name = same_method
        first_class_name, first_method_name = first_func
        second_class_name, second_method_name = second_func

        method_set = self.apkinfo.find_method(
            same_class_name, same_method_name)
        seq_table = []

        if method_set is not None:
            for method in method_set:
                for _, call, number in method.get_xref_to():

                    to_md_name = str(call.name)

                    if (to_md_name == first_method_name) or (
                            to_md_name == second_method_name):
                        seq_table.append((call.name, number))

            # sorting based on the value of the number
            if len(seq_table) < 2:
                # Not Found sequence in same_method
                return False
            seq_table.sort(key=operator.itemgetter(1))

            idx = 0
            length = len(seq_table)
            f_func_val = None
            s_func_val = None
            while idx < length:
                if seq_table[idx][0] == first_method_name:
                    f_func_val = idx
                    break
                idx += 1
            while length > 0:
                if seq_table[length - 1][0] == second_method_name:
                    s_func_val = length - 1
                    break
                length -= 1

            if s_func_val > f_func_val:
                # print("Found sequence in :" + repr(same_method))
                return True
            else:
                return False
        else:
            return False

    def check_parameter(self, common_method,
                        first_method_name, second_method_name):
        """
        check the usage of the same parameter between two method.

        :param common_method: function that call the first function and second functions at the same time.
        :param first_method_name: function which calls before the second method.
        :param second_method_name: function which calls after the first method.
        :return: True or False
        """

        pyeval = PyEval()
        # Check if there is an operation of the same register
        state = False

        common_class_name, common_method_name = common_method

        for bytecode_obj in self.apkinfo.get_method_bytecode(
                common_class_name, common_method_name
        ):
            # ['new-instance', 'v4', Lcom/google/progress/SMSHelper;]
            instruction = [bytecode_obj.mnemonic]
            if bytecode_obj.registers is not None:
                instruction.extend(bytecode_obj.registers)
            if bytecode_obj.parameter is not None:
                instruction.append(bytecode_obj.parameter)

            # for the case of MUTF8String
            instruction = [str(x) for x in instruction]

            if instruction[0] in pyeval.eval.keys():
                pyeval.eval[instruction[0]](instruction)

        for table in pyeval.show_table():
            for val_obj in table:
                matchers = [first_method_name, second_method_name]
                matching = [
                    s for s in val_obj.called_by_func if all(xs in s for xs in matchers)
                ]
                if matching:
                    state = True
                    break
        return state

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """

        # Level 1
        if set(rule_obj.x1_permission).issubset(set(self.apkinfo.permissions)):
            rule_obj.check_item[0] = True
        else:
            # Exit if the level 1 stage check fails.
            return

        # Level 2
        test_md0 = rule_obj.x2n3n4_comb[0]["method"]
        test_cls0 = rule_obj.x2n3n4_comb[0]["class"]
        test_md1 = rule_obj.x2n3n4_comb[1]["method"]
        test_cls1 = rule_obj.x2n3n4_comb[1]["class"]

        first_method_result = self.apkinfo.find_method(test_cls0, test_md0)
        second_method_result = self.apkinfo.find_method(test_cls1, test_md1)

        self.level_2_reuslt.clear()

        if first_method_result is not None or second_method_result is not None:
            rule_obj.check_item[1] = True

            if first_method_result is not None:
                self.level_2_reuslt.append((test_cls0, test_md0))
            if second_method_result is not None:
                self.level_2_reuslt.append((test_cls1, test_md1))
        else:
            # Exit if the level 2 stage check fails.
            return

        # Level 3
        if first_method_result is not None and second_method_result is not None:
            rule_obj.check_item[2] = True
        else:
            # Exit if the level 3 stage check fails.
            return

        # Level 4
        # [('class_a','method_a'),('class_b','method_b')]
        # Looking for the first layer of the upperfunction
        upperfunc0 = self.apkinfo.upperfunc(test_cls0, test_md0)
        upperfunc1 = self.apkinfo.upperfunc(test_cls1, test_md1)

        same = self.find_intersection(upperfunc0, upperfunc1)

        if same is not None:

            # Clear the results from the previous rule
            self.same_sequence_show_up.clear()
            self.same_operation.clear()

            for common_method in same:

                base_method_0 = (test_cls0, test_md0)
                base_method_1 = (test_cls1, test_md1)
                # Clear the results from the previous common_method
                self.pre_method0.clear()
                self.pre_method1.clear()
                self.find_previous_method(
                    base_method_0, common_method, self.pre_method0)
                self.find_previous_method(
                    base_method_1, common_method, self.pre_method1)
                # TODO It may have many previous method in
                # self.pre_method
                pre_0 = self.pre_method0[0]
                pre_1 = self.pre_method1[0]

                if self.check_sequence(common_method, pre_0, pre_1):
                    rule_obj.check_item[3] = True
                    self.same_sequence_show_up.append(common_method)

                    # Level 5
                    if self.check_parameter(common_method, str(pre_0[1]), str(pre_1[1])):
                        rule_obj.check_item[4] = True
                        self.same_operation.append(common_method)

        else:
            # Exit if the level 4 stage check fails.
            return

    def show_summary_report(self, rule_obj):
        """
        Show the summary report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        self.tb.add_row([green(rule_obj.crime), yellow(
            confidence), score, red(weight)])

        # add the weight
        self.weight_sum += weight
        # add the score
        self.score_sum += score

    def show_detail_report(self, rule_obj):
        """
        Show the detail report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """

        # Count the confidence
        print("")
        print(f"Confidence: {rule_obj.check_item.count(True) * 20}%")
        print("")

        if rule_obj.check_item[0]:

            print(red(CHECK_LIST), end="")
            print(green(bold("1.Permission Request")), end="")
            print("")

            for permission in rule_obj.x1_permission:
                print(f"\t\t {permission}")
        if rule_obj.check_item[1]:
            print(red(CHECK_LIST), end="")
            print(green(bold("2.Native API Usage")), end="")
            print("")

            for class_name, method_name in self.level_2_reuslt:
                print(f"\t\t ({class_name}, {method_name})")
        if rule_obj.check_item[2]:
            print(red(CHECK_LIST), end="")
            print(green(bold("3.Native API Combination")), end="")

            print("")
            print(f"\t\t ({rule_obj.x2n3n4_comb[0]['class']}, {rule_obj.x2n3n4_comb[0]['method']})")
            print(f"\t\t ({rule_obj.x2n3n4_comb[1]['class']}, {rule_obj.x2n3n4_comb[1]['method']})")
        if rule_obj.check_item[3]:

            print(red(CHECK_LIST), end="")
            print(green(bold("4.Native API Sequence")), end="")

            print("")
            print(f"\t\t Sequence show up in:")
            for seq_method in self.same_sequence_show_up:
                print(f"\t\t {repr(seq_method)}")
        if rule_obj.check_item[4]:

            print(red(CHECK_LIST), end="")
            print(green(bold("5.Native API Use Same Parameter")), end="")
            print("")
            for seq_operation in self.same_operation:
                print(f"\t\t {repr(seq_operation)}")


if __name__ == "__main__":
    pass
