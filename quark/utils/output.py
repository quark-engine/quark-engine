# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
from collections import defaultdict

from prettytable import PrettyTable
from quark.utils.colors import green, red


def _collect_analysis_data(call_graph_analysis_list, search_depth=3):
    report_dict = defaultdict(set)

    for item in call_graph_analysis_list:
        key = _get_function_display_name(item["parent"])
        description = item["crime"]
        report_dict[key].add(description)

    parent_set = {item["parent"] for item in call_graph_analysis_list}

    for parent in parent_set:
        called_function_set = set()
        expand_queue = {parent}
        for _ in range(search_depth):
            for function in expand_queue:
                next_expand_queue = {
                    child_function
                    for _, child_function, _ in function.get_xref_to()
                }
                called_function_set.update(next_expand_queue)
                expand_queue = next_expand_queue

        referenced_set = called_function_set.intersection(parent_set)
        referenced_set.discard(parent)

        for function in referenced_set:
            key = _get_function_display_name(parent)
            description = f"Call {_get_function_display_name(function)}"
            report_dict[key].add(description)

    for parent in report_dict:
        report_dict[parent] = list(report_dict[parent])

    return report_dict


def _get_function_display_name(function):
    return f"{function.class_name}{function.name}"


def output_parent_function_table(call_graph_analysis_list, search_depth):
    dd = _collect_analysis_data(call_graph_analysis_list, search_depth)

    # Pretty Table Output

    for parent, crimes in dd.items():
        tb = PrettyTable()
        tb.field_names = [
            "Parent Function",
            f"{green(parent)}",
        ]
        tb.align = "l"

        for count, crime in enumerate(set(crimes), start=1):
            if count == 1:
                tb.add_row(["Crime Description", red(f"* {crime}")])
            else:
                tb.add_row(["", red(f"* {crime}")])
        print(tb)


def output_parent_function_json(call_graph_analysis_list, search_depth):
    dd = _collect_analysis_data(call_graph_analysis_list, search_depth)

    # Json Output

    data = {"rules_classification": []}

    for parent, crimes in dd.items():
        data["rules_classification"].append(
            {
                "parent": parent,
                "crime": crimes,
            }
        )

    with open("rules_classification.json", "w") as outfile:
        json.dump(data, outfile)
