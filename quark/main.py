import argparse
import operator
import os

from androguard.misc import AnalyzeAPK
from prettytable import PrettyTable
from tqdm import tqdm

from quark.Evaluator.pyeval import PyEval
from quark.Objects.BytecodeObject import BytecodeObject
from quark.Objects.RuleObject import RuleObject
from quark.logo import logo
from quark.utils.colors import (
    red,
    bold,
    yellow,
    green,
    COLOR_OUTPUT_RED,
    COLOR_OUTPUT_GREEN,
)
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.tools import remove_dup_list
from quark.utils.weight import Weight

MAX_SEARCH_LAYER = 3
CHECK_LIST = "".join(["\t[" + u"\u2713" + "]"])

class XRule:
    def __init__(self, apk):

        self.a, self.d, self.dx = AnalyzeAPK(apk)

        # Create Class, Method, String and Field
        # crossreferences for all classes in the Analysis.
        # self.dx.create_xref()

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

    def upperFunc(self, class_name, method_name):
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

            return remove_dup_list(result)
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
                        bytecode_obj = BytecodeObject(ins.get_name(), reg_list, None,)
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

    def find_f_previous_method(self, base, top):
        """
        Find the previous method based on base method
        before top method.

        This will append the method into self.pre_method0
        :param base:
        :param top:
        :return: None
        """

        method_set = self.upperFunc(base[0], base[1])

        if method_set is not None:

            if top in method_set:
                self.pre_method0.append(base)
            else:
                for item in method_set:
                    self.find_f_previous_method(item, top)

    def find_s_previous_method(self, base, top):
        """
        Find the previous method based on base method
        before top method.

        This will append the method into self.pre_method1
        :param base:
        :param top:
        :return: None
        """

        method_set = self.upperFunc(base[0], base[1])

        if method_set is not None:
            if top in method_set:
                self.pre_method1.append(base)
            else:
                for item in method_set:
                    self.find_s_previous_method(item, top)

    def find_intersection(self, list1, list2, depth=1):
        """
        Find the list1 ∩ list2.

        list1 & list2 are list within tuple, for example,
        [("class_name","method_name"),...]

        :param list1:
        :param list2:
        :param depth: MAX recursion
        :return:
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
                    if self.upperFunc(item[0], item[1]) is not None:
                        next_list1 = self.upperFunc(item[0], item[1])
                for item in list2:
                    if self.upperFunc(item[0], item[1]) is not None:
                        next_list2.extend(self.upperFunc(item[0], item[1]))
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

        :param same_method: the tuple with (class_name, method_name)
        :param f_func: the first show up function, which is (class_name, method_name)
        :param s_func: the tuple with (class_name, method_name)
        :return: boolean
        """

        method_set = self.find_method(same_method[0], same_method[1])
        seq_table = []

        if method_set is not None:
            for md in method_set:
                for _, call, number in md.get_xref_to():

                    to_md_name = str(call.name)

                    if (to_md_name == f_func[1]) or (to_md_name == s_func[1]):
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
                # print("Found sequence in :" + repr(same_method))
                return True
            else:
                return False

    def check_parameter(self, common_method, fist_method_name, second_method_name):
        """
        check the usage of the same parameter between
        two method.

        :param common_method: ("class_name", "method_name")
        :param fist_method_name:
        :param second_method_name:
        :return:
        """

        pyeval = PyEval()
        # Check if there is an operation of the same register
        state = False

        for bytecode_obj in self.get_method_bytecode(
            common_method[0], common_method[1]
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
        Run the five levels check to get the y_score.
        :param rule_obj:
        :return:
        """

        # Level 1
        if set(rule_obj.x1_permission).issubset(set(self.permissions)):
            rule_obj.check_item[0] = True

        # Level 2
        test_md0 = rule_obj.x2n3n4_comb[0]["method"]
        test_cls0 = rule_obj.x2n3n4_comb[0]["class"]
        if self.find_method(test_cls0, test_md0) is not None:
            rule_obj.check_item[1] = True
            # Level 3
            test_md1 = rule_obj.x2n3n4_comb[1]["method"]
            test_cls1 = rule_obj.x2n3n4_comb[1]["class"]
            if self.find_method(test_cls1, test_md1) is not None:
                rule_obj.check_item[2] = True

                # Level 4
                # [('class_a','method_a'),('class_b','method_b')]
                # Looking for the first layer of the upperfunction
                upperfunc0 = self.upperFunc(test_cls0, test_md0)
                upperfunc1 = self.upperFunc(test_cls1, test_md1)

                same = self.find_intersection(upperfunc0, upperfunc1)
                if same is not None:

                    for common_method in same:

                        base_method_0 = (test_cls0, test_md0)
                        base_method_1 = (test_cls1, test_md1)
                        self.pre_method0.clear()
                        self.pre_method1.clear()
                        self.find_f_previous_method(base_method_0, common_method)
                        self.find_s_previous_method(base_method_1, common_method)
                        # TODO It may have many previous method in self.pre_method
                        pre_0 = self.pre_method0[0]
                        pre_1 = self.pre_method1[0]

                        if self.check_sequence(common_method, pre_0, pre_1):
                            rule_obj.check_item[3] = True
                            self.same_sequence_show_up.append(common_method)

                            # Level 5
                            if self.check_parameter(
                                common_method, str(pre_0[1]), str(pre_1[1])
                            ):
                                rule_obj.check_item[4] = True
                                self.same_operation.append(common_method)

    def show_easy_report(self, rule_obj):
        """
        Show the summary report.

        :param rule_obj:
        :return:
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        self.tb.add_row([green(rule_obj.crime), yellow(confidence), score, red(weight)])

        # add the weight
        self.weight_sum += weight
        # add the score
        self.score_sum += score

    def show_detail_report(self, rule_obj):
        """
        Show the detail report

        :param rule_obj:
        :return:
        """

        # Count the confidence
        print("")
        print("Confidence:" + str(rule_obj.check_item.count(True) * 20) + "%")
        print("")

        if rule_obj.check_item[0]:

            COLOR_OUTPUT_RED(CHECK_LIST)
            COLOR_OUTPUT_GREEN(bold("1.Permission Request"))
            print("")

            for permission in rule_obj.x1_permission:
                print("\t\t" + permission)
        if rule_obj.check_item[1]:
            COLOR_OUTPUT_RED(CHECK_LIST)
            COLOR_OUTPUT_GREEN(bold("2.Native API Usage"))
            print("")
            print("\t\t" + rule_obj.x2n3n4_comb[0]["method"])
        if rule_obj.check_item[2]:
            COLOR_OUTPUT_RED(CHECK_LIST)
            COLOR_OUTPUT_GREEN(bold("3.Native API Combination"))

            print("")
            print("\t\t" + rule_obj.x2n3n4_comb[0]["method"])
            print("\t\t" + rule_obj.x2n3n4_comb[1]["method"])
        if rule_obj.check_item[3]:

            COLOR_OUTPUT_RED(CHECK_LIST)
            COLOR_OUTPUT_GREEN(bold("4.Native API Sequence"))

            print("")
            print("\t\t" + "Sequence show up in:")
            for seq_methon in self.same_sequence_show_up:
                print("\t\t" + repr(seq_methon))
        if rule_obj.check_item[4]:

            COLOR_OUTPUT_RED(CHECK_LIST)
            COLOR_OUTPUT_GREEN(bold("5.Native API Use Same Parameter"))
            print("")
            for seq_operation in self.same_operation:
                print("\t\t" + repr(seq_operation))


def main():
    logo()

    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--easy", action="store_true", help="show easy report")
    parser.add_argument(
        "-d", "--detail", action="store_true", help="show detail report"
    )
    parser.add_argument("-a", "--apk", help="APK file", required=True)
    parser.add_argument(
        "-r", "--rule", help="Rules folder need to be checked", required=True
    )

    ans = parser.parse_args()

    if ans.easy:

        # Load APK
        data = XRule(ans.apk)

        # Load rules
        rules_list = os.listdir(ans.rule)

        for rule in tqdm(rules_list):
            rulepath = os.path.join(ans.rule, rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_easy_report(rule_checker)

        w = Weight(data.score_sum, data.weight_sum)
        print_warning(w.calculate())
        print_info("Total Score: " + str(data.score_sum))
        print(data.tb)

    elif ans.detail:

        # Load APK
        data = XRule(ans.apk)

        # Load rules
        rules_list = os.listdir(ans.rule)

        for rule in tqdm(rules_list):
            rulepath = os.path.join(ans.rule, rule)
            print(rulepath)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_detail_report(rule_checker)
            print_success("OK")
    else:
        print("python3 main.py --help")


if __name__ == "__main__":
    main()
