# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import operator
import os

import numpy as np
import pandas as pd

from quark.core.analysis import QuarkAnalysis
from quark.core.apkinfo import AndroguardImp
from quark.core.rzapkinfo import RizinImp
from quark.evaluator.pyeval import PyEval
from quark.utils import tools
from quark.utils.colors import (
    colorful_report,
    green,
    lightblue,
    lightyellow,
    magenta,
    red,
    yellow,
)
from quark.utils.graph import call_graph
from quark.utils.output import (
    get_rule_classification_data,
    output_parent_function_graph,
    output_parent_function_json,
    output_parent_function_table,
)
from quark.utils.pprint import print_info, print_success, print_warning
from quark.utils.weight import Weight

MAX_SEARCH_LAYER = 3


class Quark:
    """Quark module is used to check quark's five-stage theory"""

    def __init__(self, apk, core_library="androguard"):
        """

        :param apk: the filename of the apk.
        """
        core_library = core_library.lower()
        if core_library == "rizin":
            self.apkinfo = RizinImp(apk)
        elif core_library == "androguard":
            self.apkinfo = AndroguardImp(apk)
        else:
            raise ValueError(
                f"Unsupported core library for Quark: {core_library}"
            )

        self.quark_analysis = QuarkAnalysis()

    def find_previous_method(
        self, base_method, parent_function, wrapper, visited_methods=None
    ):
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
                    self.find_previous_method(
                        item, parent_function, wrapper, visited_methods
                    )

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

        if not first_method_set or not second_method_set:
            raise ValueError("Set is Null")
        # find ∩
        result = first_method_set & second_method_set
        if result:
            return result
        else:
            return self.method_recursive_search(
                depth, first_method_set, second_method_set
            )

    def method_recursive_search(
        self, depth, first_method_set, second_method_set
    ):
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
                next_level_set_1 = (
                    self.apkinfo.upperfunc(method) | next_level_set_1
                )
        for method in second_method_set:
            if self.apkinfo.upperfunc(method):
                next_level_set_2 = (
                    self.apkinfo.upperfunc(method) | next_level_set_2
                )

        return self.find_intersection(
            next_level_set_1, next_level_set_2, depth
        )

    def check_sequence(
        self, mutual_parent, first_method_list, second_method_list
    ):
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

                seq_table = [
                    (call, number)
                    for call, number in self.apkinfo.lowerfunc(mutual_parent)
                    if call in (first_call_method, second_call_method)
                ]

                # sorting based on the value of the number
                if len(seq_table) < 2:
                    # Not Found sequence in same_method
                    continue
                seq_table.sort(key=operator.itemgetter(1))
                # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

                method_list_need_check = [x[0] for x in seq_table]
                sequence_pattern_method = [
                    first_call_method,
                    second_call_method,
                ]

                if tools.contains(
                    sequence_pattern_method, method_list_need_check
                ):
                    state = True

                    # Record the mapping between the parent function and the wrapper method
                    self.quark_analysis.parent_wrapper_mapping[
                        mutual_parent.full_name
                    ] = self.apkinfo.get_wrapper_smali(
                        mutual_parent, first_call_method, second_call_method
                    )

        return state

    def check_parameter(
        self,
        parent_function,
        first_method_list,
        second_method_list,
        keyword_item_list=None,
    ):
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

                pyeval = PyEval(self.apkinfo)
                # Check if there is an operation of the same register

                for bytecode_obj in self.apkinfo.get_method_bytecode(
                    parent_function
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

                        for c_func in val_obj.called_by_func:

                            first_method_pattern = f"{first_call_method.class_name}->{first_call_method.name}{first_call_method.descriptor}"
                            second_method_pattern = f"{second_call_method.class_name}->{second_call_method.name}{second_call_method.descriptor}"

                            if (
                                first_method_pattern in c_func
                                and second_method_pattern in c_func
                            ):
                                state = True

                                if keyword_item_list and any(
                                    keyword_item_list
                                ):
                                    self.check_parameter_values(
                                        c_func,
                                        (
                                            first_method_pattern,
                                            second_method_pattern,
                                        ),
                                        keyword_item_list,
                                    )

                                # Record the mapping between the parent function and the wrapper method
                                self.quark_analysis.parent_wrapper_mapping[
                                    parent_function.full_name
                                ] = self.apkinfo.get_wrapper_smali(
                                    parent_function,
                                    first_call_method,
                                    second_call_method,
                                )

                # Build for the call graph
                if state:
                    call_graph_analysis = {
                        "parent": parent_function,
                        "first_call": first_call_method,
                        "second_call": second_call_method,
                        "apkinfo": self.apkinfo,
                        "first_api": self.quark_analysis.first_api,
                        "second_api": self.quark_analysis.second_api,
                        "crime": self.quark_analysis.crime_description,
                    }
                    self.quark_analysis.call_graph_analysis_list.append(
                        call_graph_analysis
                    )

        return state

    @staticmethod
    def check_parameter_values(source_str, pattern_list, keyword_item_list):
        for pattern, keyword_item in zip(pattern_list, keyword_item_list):
            if keyword_item is None:
                continue

            start_index = source_str.index(pattern) + len(pattern)

            end_index = -1
            brackets_count = 1
            for idx, char in enumerate(source_str[start_index:]):
                if char == "(":
                    brackets_count += 1
                elif char == ")":
                    brackets_count -= 1

                if brackets_count == 0:
                    end_index = idx + start_index
                    break

            parameter_str = source_str[start_index:end_index]

            for keyword in keyword_item:
                if str(keyword) not in parameter_str:
                    return False

        return True

    def find_api_usage(self, class_name, method_name, descriptor_name):
        method_list = []

        # Source method
        source_method = self.apkinfo.find_method(
            class_name, method_name, descriptor_name
        )
        if source_method:
            return [source_method]

        # Potential Method
        potential_method_list = [
            method
            for method in self.apkinfo.all_methods
            if method.name == method_name
            and method.descriptor == descriptor_name
        ]

        potential_method_list = [
            method
            for method in potential_method_list
            if not next(self.apkinfo.get_method_bytecode(method), None)
        ]

        # Check if each method's class is a subclass of the given class
        for method in potential_method_list:
            current_class_set = {method.class_name}

            while current_class_set and not current_class_set.intersection(
                {class_name, "Ljava/lang/Object;"}
            ):
                next_class_set = set()
                for clazz in current_class_set:
                    next_class_set.update(
                        self.apkinfo.superclass_relationships[clazz]
                    )

                current_class_set = next_class_set

            current_class_set.discard("Ljava/lang/Object;")
            if current_class_set:
                method_list.append(method)

        return method_list

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        self.quark_analysis.clean_result()
        self.quark_analysis.crime_description = rule_obj.crime

        # Level 1: Permission Check
        if self.apkinfo.ret_type == "DEX":
            rule_obj.check_item[0] = True
        elif set(rule_obj.permission).issubset(set(self.apkinfo.permissions)):
            rule_obj.check_item[0] = True
        else:
            # Exit if the level 1 stage check fails.
            return

        # Level 2: Single Native API Check
        api_1_method_name = rule_obj.api[0]["method"]
        api_1_class_name = rule_obj.api[0]["class"]
        api_1_descriptor = rule_obj.api[0]["descriptor"]

        api_2_method_name = rule_obj.api[1]["method"]
        api_2_class_name = rule_obj.api[1]["class"]
        api_2_descriptor = rule_obj.api[1]["descriptor"]

        first_api_list = self.find_api_usage(
            api_1_class_name, api_1_method_name, api_1_descriptor
        )
        second_api_list = self.find_api_usage(
            api_2_class_name, api_2_method_name, api_2_descriptor
        )

        if not first_api_list and not second_api_list:
            # Exit if the level 2 stage check fails.
            return

        else:
            rule_obj.check_item[1] = True

        if first_api_list:
            self.quark_analysis.level_2_result.append(first_api_list[0])
        if second_api_list:
            self.quark_analysis.level_2_result.append(second_api_list[0])

        # Level 3: Both Native API Check
        if not (first_api_list and second_api_list):
            # Exit if the level 3 stage check fails.
            return

        self.quark_analysis.first_api = first_api_list[0]
        self.quark_analysis.second_api = second_api_list[0]
        rule_obj.check_item[2] = True

        self.quark_analysis.level_3_result = [set(), set()]

        # Level 4: Sequence Check
        for first_api in first_api_list:
            for second_api in second_api_list:
                # Looking for the first layer of the upper function
                first_api_xref_from = self.apkinfo.upperfunc(first_api)
                second_api_xref_from = self.apkinfo.upperfunc(second_api)

                self.quark_analysis.level_3_result[0].update(
                    first_api_xref_from
                )
                self.quark_analysis.level_3_result[1].update(
                    second_api_xref_from
                )

                if not first_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of {first_api}"
                    )
                    continue
                if not second_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of{second_api}"
                    )
                    continue

                mutual_parent_function_list = self.find_intersection(
                    first_api_xref_from, second_api_xref_from
                )

                if mutual_parent_function_list is None:
                    # Exit if the level 4 stage check fails.
                    return
                for parent_function in mutual_parent_function_list:
                    first_wrapper = []
                    second_wrapper = []

                    self.find_previous_method(
                        first_api, parent_function, first_wrapper
                    )
                    self.find_previous_method(
                        second_api, parent_function, second_wrapper
                    )

                    if self.check_sequence(
                        parent_function, first_wrapper, second_wrapper
                    ):
                        rule_obj.check_item[3] = True
                        self.quark_analysis.level_4_result.append(
                            parent_function
                        )

                        keyword_item_list = (
                            rule_obj.api[i].get("keyword", None)
                            for i in range(2)
                        )

                        # Level 5: Handling The Same Register Check
                        if self.check_parameter(
                            parent_function,
                            first_wrapper,
                            second_wrapper,
                            keyword_item_list=keyword_item_list,
                        ):
                            rule_obj.check_item[4] = True
                            self.quark_analysis.level_5_result.append(
                                parent_function
                            )

    def get_json_report(self):
        """
        Get quark report including summary and detail with json format.

        :return: json report
        """

        w = Weight(
            self.quark_analysis.score_sum, self.quark_analysis.weight_sum
        )
        warning = w.calculate()

        # Filter out color code in threat level
        for level in ["Low Risk", "Moderate Risk", "High Risk"]:
            if level in warning:
                warning = level

        return {
            "md5": self.apkinfo.md5,
            "apk_filename": self.apkinfo.filename,
            "size_bytes": self.apkinfo.filesize,
            "threat_level": warning,
            "total_score": self.quark_analysis.score_sum,
            "crimes": self.quark_analysis.json_report,
        }

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
        score = rule_obj.score

        # Assign level 1 examine result
        permissions = rule_obj.permission if rule_obj.check_item[0] else []

        # Assign level 2 examine result
        api = []
        if rule_obj.check_item[1]:
            for item2 in self.quark_analysis.level_2_result:
                api.append(
                    {
                        "class": str(item2.class_name),
                        "method": str(item2.name),
                        "descriptor": str(item2.descriptor),
                    }
                )

        # Assign level 3 examine result
        combination = []
        if rule_obj.check_item[2]:
            combination = rule_obj.api

        # Assign level 4 - 5 examine result if exist
        sequnce_show_up = []
        same_operation_show_up = []

        # Check examination has passed level 4
        if self.quark_analysis.level_4_result and rule_obj.check_item[3]:
            for item4 in self.quark_analysis.level_4_result:
                sequnce_show_up.append(
                    {
                        item4.full_name: self.quark_analysis.parent_wrapper_mapping[
                            item4.full_name
                        ]
                    }
                )

            # Check examination has passed level 5
            if self.quark_analysis.level_5_result and rule_obj.check_item[4]:
                for item5 in self.quark_analysis.level_5_result:
                    same_operation_show_up.append(
                        {
                            item5.full_name: self.quark_analysis.parent_wrapper_mapping[
                                item5.full_name
                            ]
                        }
                    )

        crime = {
            "rule": rule_obj.rule_filename,
            "crime": rule_obj.crime,
            "label": rule_obj.label,
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

    def add_table_row(self, name, rule_obj, confidence, score, weight):

        self.quark_analysis.summary_report_table.add_row(
            [
                name,
                green(rule_obj.crime),
                yellow(confidence),
                score,
                red(weight),
            ]
        )

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
        score = rule_obj.score
        name = rule_obj.rule_filename

        if threshold:

            if rule_obj.check_item.count(True) * 20 >= int(threshold):
                self.add_table_row(name, rule_obj, confidence, score, weight)

        else:
            self.add_table_row(name, rule_obj, confidence, score, weight)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

    def show_label_report(self, rule_path, all_labels, table_version):
        """
        Show the report based on label, last column represents max confidence for that label
        :param rule_path: the path where may be present the file label_desc.csv.
        :param all_labels: dictionary containing label:<array of confidence values associated to that label>
        :return: None
        """
        label_desc = {}
        # clear table to manage max/detail version
        self.quark_analysis.label_report_table.clear()
        if os.path.isfile(os.path.join(rule_path, "label_desc.csv")):
            # associate to each label a description
            col_list = ["label", "description"]
            # csv file on form <label,description>
            # put this file in the folder of rules (it must not be a json file since it could create conflict with management of rules)
            df = pd.read_csv(
                os.path.join(rule_path, "label_desc.csv"), usecols=col_list
            )
            label_desc = dict(zip(df["label"], df["description"]))

        for label_name in all_labels:
            confidences = np.array(all_labels[label_name])

            if table_version == "max":
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                    ]
                )
            else:
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                    "AVG Confidence",
                    "Std Deviation",
                    "# of Rules with Confidence >= 80%",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                        magenta(round(np.mean(confidences), 2)),
                        lightblue(round(np.std(confidences), 2)),
                        lightyellow(np.count_nonzero(confidences >= 80)),
                    ]
                )

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

            colorful_report("1.Permission Request")
            for permission in rule_obj.permission:
                print(f"\t\t {permission}")
        if rule_obj.check_item[1]:
            colorful_report("2.Native API Usage")
            for api in self.quark_analysis.level_2_result:
                print(f"\t\t {api.full_name}")
        if rule_obj.check_item[2]:
            colorful_report("3.Native API Combination")
            for numbered_api, method_list in zip(
                ("First API", "Second API"), self.quark_analysis.level_3_result
            ):
                print(f"\t\t {numbered_api} show up in:")
                if method_list:
                    for comb_method in method_list:
                        print(f"\t\t {comb_method.full_name}")
                else:
                    print("\t\t None")

        if rule_obj.check_item[3]:

            colorful_report("4.Native API Sequence")
            print("\t\t Sequence show up in:")
            for seq_method in self.quark_analysis.level_4_result:
                print(f"\t\t {seq_method.full_name}")
        if rule_obj.check_item[4]:

            colorful_report("5.Native API Use Same Parameter")
            for seq_operation in self.quark_analysis.level_5_result:
                print(f"\t\t {seq_operation.full_name}")

    def show_call_graph(self, output_format=None):
        print_info("Creating Call Graph...")
        for (
            call_graph_analysis
        ) in self.quark_analysis.call_graph_analysis_list:
            call_graph(call_graph_analysis, output_format)
        print_success("Call Graph Completed")

    def show_rule_classification(self):
        print_info("Rules Classification")

        data_bundle = get_rule_classification_data(
            self.quark_analysis.call_graph_analysis_list, MAX_SEARCH_LAYER
        )

        output_parent_function_table(data_bundle)
        output_parent_function_json(data_bundle)
        output_parent_function_graph(data_bundle)


if __name__ == "__main__":
    pass
