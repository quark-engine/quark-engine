# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import operator

from quark.Evaluator.pyeval import PyEval
from quark.Objects.analysis import QuarkAnalysis
from quark.Objects.apkinfo import Apkinfo
from quark.utils import tools
from quark.utils.colors import (
    red,
    bold,
    yellow,
    green,
)
from quark.utils.graph import call_graph
from quark.utils.out import print_info, print_success
from quark.utils.output import output_parent_function_table, output_parent_function_json
from quark.utils.weight import Weight

MAX_SEARCH_LAYER = 3
CHECK_LIST = "".join(["\t[" + "\u2713" + "]"])


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk):
        """

        :param apk: the filename of the apk.
        """
        self.apkinfo = Apkinfo(apk)

        self.quark_analysis = QuarkAnalysis()

    def find_previous_method(self, base_method, parent_function, wrapper, visited_methods=None):
        """
        Find the method under the parent function, based on base_method before to parent_function.
        This will append the method into wrapper.

        :param base_method: the base function which needs to be searched.
        :param parent_function: the top-level function which calls the basic function.
        :param wrapper: list is used to track each function.
        :param visited_methods: set with tested method.
        :return: None
        """
        if visited_methods is None:
            visited_methods = set()

        method_set = self.apkinfo.upperfunc(base_method)
        visited_methods.add(base_method)

        if method_set is not None:

            if parent_function in method_set:
                wrapper.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(item, parent_function, wrapper, visited_methods)

    def find_intersection(self, first_method_set, second_method_set, depth=1):
        """
        Find the first_method_list ∩ second_method_list.
        [MethodAnalysis, MethodAnalysis,...]

        :param first_method_set: first list that contains each MethodAnalysis.
        :param second_method_set: second list that contains each MethodAnalysis.
        :param depth: maximum number of recursive search functions.
        :return: a set of first_method_list ∩ second_method_list or None.
        """
        # Check both lists are not null

        if first_method_set and second_method_set:

            # find ∩
            result = first_method_set & second_method_set
            if result:
                return result
            else:
                # Not found same method usage, try to find the next layer.
                depth += 1
                if depth > MAX_SEARCH_LAYER:
                    return None

                # Append first layer into next layer.
                next_level_set_1 = first_method_set.copy()
                next_level_set_2 = second_method_set.copy()

                # Extend the xref from function into next layer.
                for method in first_method_set:
                    if self.apkinfo.upperfunc(method):
                        next_level_set_1 = self.apkinfo.upperfunc(method) | next_level_set_1
                for method in second_method_set:
                    if self.apkinfo.upperfunc(method):
                        next_level_set_2 = self.apkinfo.upperfunc(method) | next_level_set_2

                return self.find_intersection(next_level_set_1, next_level_set_2, depth)
        else:
            raise ValueError("Set is Null")

    def check_sequence(self, mutual_parent, first_method_list, second_method_list):
        """
        Check if the first function appeared before the second function.

        :param mutual_parent: function that call the first function and second functions at the same time.
        :param first_method_list: the first show up function, which is a MethodAnalysis
        :param second_method_list: the second show up function, which is a MethodAnalysis
        :return: True or False
        """
        state = False

        for first_call_method in first_method_list:
            for second_call_method in second_method_list:

                seq_table = []

                for _, call, number in mutual_parent.get_xref_to():

                    if call in (first_call_method, second_call_method):
                        seq_table.append((call, number))

                # sorting based on the value of the number
                if len(seq_table) < 2:
                    # Not Found sequence in same_method
                    continue
                seq_table.sort(key=operator.itemgetter(1))
                # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

                method_list_need_check = [x[0] for x in seq_table]
                sequence_pattern_method = [first_call_method, second_call_method]

                if tools.contains(sequence_pattern_method, method_list_need_check):
                    state = True

                    # Record the mapping between the parent function and the wrapper method
                    self.quark_analysis.parent_wrapper_mapping[
                        mutual_parent.full_name] = self.apkinfo.get_wrapper_smali(mutual_parent,
                                                                                  first_call_method,
                                                                                  second_call_method)

        return state

    def check_parameter(self, parent_function, first_method_list, second_method_list):
        """
        Check the usage of the same parameter between two method.

        :param parent_function: function that call the first function and second functions at the same time.
        :param first_method_list: function which calls before the second method.
        :param second_method_list: function which calls after the first method.
        :return: True or False
        """
        state = False

        for first_call_method in first_method_list:
            for second_call_method in second_method_list:

                pyeval = PyEval()
                # Check if there is an operation of the same register

                for bytecode_obj in self.apkinfo.get_method_bytecode(parent_function):
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

                        for c_func in val_obj.called_by_func:

                            first_method_pattern = f"{first_call_method.class_name}->{first_call_method.name}{first_call_method.descriptor}"
                            second_method_pattern = f"{second_call_method.class_name}->{second_call_method.name}{second_call_method.descriptor}"

                            if first_method_pattern in c_func and second_method_pattern in c_func:
                                state = True

                                # Record the mapping between the parent function and the wrapper method
                                self.quark_analysis.parent_wrapper_mapping[
                                    parent_function.full_name] = self.apkinfo.get_wrapper_smali(
                                    parent_function,
                                    first_call_method,
                                    second_call_method)

                # Build for the call graph
                if state:
                    call_graph_analysis = {"parent": parent_function,
                                           "first_call": first_call_method,
                                           "second_call": second_call_method,
                                           "apkinfo": self.apkinfo,
                                           "first_api": self.quark_analysis.first_api,
                                           "second_api": self.quark_analysis.second_api,
                                           "crime": self.quark_analysis.crime_description,
                                           }
                    self.quark_analysis.call_graph_analysis_list.append(call_graph_analysis)

        return state

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        self.quark_analysis.clean_result()
        self.quark_analysis.crime_description = rule_obj.crime

        # Level 1: Permission Check
        if set(rule_obj.x1_permission).issubset(set(self.apkinfo.permissions)):
            rule_obj.check_item[0] = True
        else:
            # Exit if the level 1 stage check fails.
            return

        # Level 2: Single Native API Check
        api_1_method_name = rule_obj.x2n3n4_comb[0]["method"]
        api_1_class_name = rule_obj.x2n3n4_comb[0]["class"]
        api_1_descriptor = rule_obj.x2n3n4_comb[0]["descriptor"]

        api_2_method_name = rule_obj.x2n3n4_comb[1]["method"]
        api_2_class_name = rule_obj.x2n3n4_comb[1]["class"]
        api_2_descriptor = rule_obj.x2n3n4_comb[1]["descriptor"]

        first_api = self.apkinfo.find_method(api_1_class_name, api_1_method_name, api_1_descriptor)
        second_api = self.apkinfo.find_method(api_2_class_name, api_2_method_name, api_2_descriptor)

        if first_api is not None or second_api is not None:
            rule_obj.check_item[1] = True

            if first_api is not None:
                first_api = self.apkinfo.find_method(api_1_class_name, api_1_method_name, api_1_descriptor)
                self.quark_analysis.level_2_result.append(first_api)
            if second_api is not None:
                second_api = self.apkinfo.find_method(api_2_class_name, api_2_method_name, api_2_descriptor)
                self.quark_analysis.level_2_result.append(second_api)
        else:
            # Exit if the level 2 stage check fails.
            return

        # Level 3: Both Native API Check
        if first_api is not None and second_api is not None:
            self.quark_analysis.first_api = first_api
            self.quark_analysis.second_api = second_api
            rule_obj.check_item[2] = True

        else:
            # Exit if the level 3 stage check fails.
            return

        # Level 4: Sequence Check
        # Looking for the first layer of the upper function
        first_api_xref_from = self.apkinfo.upperfunc(first_api)
        second_api_xref_from = self.apkinfo.upperfunc(second_api)

        mutual_parent_function_list = self.find_intersection(first_api_xref_from, second_api_xref_from)

        if mutual_parent_function_list is not None:

            for parent_function in mutual_parent_function_list:
                first_wrapper = []
                second_wrapper = []

                self.find_previous_method(first_api, parent_function, first_wrapper)
                self.find_previous_method(second_api, parent_function, second_wrapper)

                if self.check_sequence(parent_function, first_wrapper, second_wrapper):
                    rule_obj.check_item[3] = True
                    self.quark_analysis.level_4_result.append(parent_function)

                    # Level 5: Handling The Same Register Check
                    if self.check_parameter(parent_function, first_wrapper, second_wrapper):
                        rule_obj.check_item[4] = True
                        self.quark_analysis.level_5_result.append(parent_function)

        else:
            # Exit if the level 4 stage check fails.
            return

    def get_json_report(self):
        """
        Get quark report including summary and detail with json format.

        :return: json report
        """

        w = Weight(self.quark_analysis.score_sum, self.quark_analysis.weight_sum)
        warning = w.calculate()

        # Filter out color code in threat level
        for level in ["Low Risk", "Moderate Risk", "High Risk"]:
            if level in warning:
                warning = level

        json_report = {
            "md5": self.apkinfo.md5,
            "apk_filename": self.apkinfo.filename,
            "size_bytes": self.apkinfo.filesize,
            "threat_level": warning,
            "total_score": self.quark_analysis.score_sum,
            "crimes": self.quark_analysis.json_report,
        }

        return json_report

    def generate_json_report(self, rule_obj):
        """
        Show the json report.

        :param rule_obj: the instance of the RuleObject
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        # Assign level 1 examine result
        permissions = []
        if rule_obj.check_item[0]:
            permissions = rule_obj.x1_permission

        # Assign level 2 examine result
        api = []
        if rule_obj.check_item[1]:
            for item2 in self.quark_analysis.level_2_result:
                api.append({
                    "class": repr(item2.class_name),
                    "method": repr(item2.name),
                })

        # Assign level 3 examine result
        combination = []
        if rule_obj.check_item[2]:
            combination = rule_obj.x2n3n4_comb

        # Assign level 4 - 5 examine result if exist
        sequnce_show_up = []
        same_operation_show_up = []

        # Check examination has passed level 4
        if self.quark_analysis.level_4_result and rule_obj.check_item[3]:
            for item4 in self.quark_analysis.level_4_result:
                sequnce_show_up.append({
                    repr(item4.full_name): self.quark_analysis.parent_wrapper_mapping[item4.full_name]
                })

            # Check examination has passed level 5
            if self.quark_analysis.level_5_result and rule_obj.check_item[4]:
                for item5 in self.quark_analysis.level_5_result:
                    same_operation_show_up.append({
                        repr(item5.full_name): self.quark_analysis.parent_wrapper_mapping[item5.full_name]
                    })

        crime = {
            "crime": rule_obj.crime,
            "score": score,
            "weight": weight,
            "confidence": confidence,
            "permissions": permissions,
            "native_api": api,
            "combination": combination,
            "sequence": sequnce_show_up,
            "register": same_operation_show_up,
        }
        self.quark_analysis.json_report.append(crime)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

    def add_table_row(self, rule_obj, confidence, score, weight):

        self.quark_analysis.summary_report_table.add_row([
            green(rule_obj.crime),
            yellow(confidence),
            score,
            red(weight),
        ])

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

    def show_summary_report(self, rule_obj, threshold=None):
        """
        Show the summary report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        # Count the confidence
        confidence = f"{rule_obj.check_item.count(True) * 20}%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.yscore

        if threshold:

            if rule_obj.check_item.count(True) * 20 >= int(threshold):
                self.add_table_row(rule_obj, confidence, score, weight)

        else:
            self.add_table_row(rule_obj, confidence, score, weight)

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

            for api in self.quark_analysis.level_2_result:
                print(f"\t\t ({api.class_name}, {api.name})")
        if rule_obj.check_item[2]:
            print(red(CHECK_LIST), end="")
            print(green(bold("3.Native API Combination")), end="")

            print("")
            print(
                f"\t\t ({rule_obj.x2n3n4_comb[0]['class']}, {rule_obj.x2n3n4_comb[0]['method']})",
            )
            print(
                f"\t\t ({rule_obj.x2n3n4_comb[1]['class']}, {rule_obj.x2n3n4_comb[1]['method']})",
            )
        if rule_obj.check_item[3]:

            print(red(CHECK_LIST), end="")
            print(green(bold("4.Native API Sequence")), end="")

            print("")
            print(f"\t\t Sequence show up in:")
            for seq_method in self.quark_analysis.level_4_result:
                print(f"\t\t {seq_method.full_name}")
        if rule_obj.check_item[4]:

            print(red(CHECK_LIST), end="")
            print(green(bold("5.Native API Use Same Parameter")), end="")
            print("")
            for seq_operation in self.quark_analysis.level_5_result:
                print(f"\t\t {seq_operation.full_name}")

    def show_call_graph(self):
        print_info("Creating Call Graph...")
        for call_graph_analysis in self.quark_analysis.call_graph_analysis_list:
            call_graph(call_graph_analysis)
        print_success("Call Graph Completed")

    def show_rule_classification(self):
        print_info("Rules Classification")
        output_parent_function_table(self.quark_analysis.call_graph_analysis_list)
        output_parent_function_json(self.quark_analysis.call_graph_analysis_list)


if __name__ == "__main__":
    pass
