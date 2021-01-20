# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
from collections import defaultdict

from prettytable import PrettyTable

from quark.utils.colors import red, green


def output_parent_function_table(call_graph_analysis_list):
    dd = defaultdict(list)

    for item in call_graph_analysis_list:
        # print(item["parent"].class_name, item["parent"].name, item["crime"])
        key = f"{item['parent'].class_name}{item['parent'].name}"
        dd[key].append(item["crime"])

    # Pretty Table Output

    for parent, crimes in dd.items():
        tb = PrettyTable()
        tb.field_names = ["Parent Function", f"{green(parent)}"]
        tb.align = "l"

        count = 1

        for crime in crimes:
            if count == 1:
                tb.add_row(["Crime Description", red(f"* {crime}")])
            else:
                tb.add_row(["", red(f"* {crime}")])
            count += 1

        print(tb)


def output_parent_function_json(call_graph_analysis_list):
    dd = defaultdict(list)

    for item in call_graph_analysis_list:
        # print(item["parent"].class_name, item["parent"].name, item["crime"])
        key = f"{item['parent'].class_name}{item['parent'].name}"
        dd[key].append(item["crime"])

    # Json Output

    data = {"rules_classification": []}

    for parent, crimes in dd.items():
        data["rules_classification"].append({
            "parent": parent,
            "crime": crimes,
        })

    with open('rules_classification.json', 'w') as outfile:
        json.dump(data, outfile)
