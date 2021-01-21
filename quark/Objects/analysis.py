# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from collections import defaultdict

from prettytable import PrettyTable


def init_pretty_table():
    # Pretty Table Output
    tb = PrettyTable()
    tb.field_names = ["Rule", "Confidence", "Score", "Weight"]
    tb.align = "l"
    return tb


class QuarkAnalysis:
    __slots__ = ["crime_description", "first_api", "second_api", "level_1_result", "level_2_result", "level_3_result",
                 "level_4_result", "level_5_result", "json_report", "weight_sum", "score_sum", "summary_report_table",
                 "call_graph_analysis_list", "parent_wrapper_mapping"]

    def __init__(self):
        self.crime_description = ""
        self.first_api = None
        self.second_api = None
        self.level_1_result = []
        self.level_2_result = []
        self.level_3_result = []
        self.level_4_result = []
        self.level_5_result = []

        # Json report
        self.json_report = []
        # Sum of the each weight
        self.weight_sum = 0
        # Sum of the each rule
        self.score_sum = 0
        self.summary_report_table = init_pretty_table()
        # Call graph analysis
        self.call_graph_analysis_list = []

        # Mapping between the parent function and the wrapper method
        self.parent_wrapper_mapping = defaultdict(str)

    def clean_result(self):
        self.level_1_result.clear()
        self.level_2_result.clear()
        self.level_3_result.clear()
        self.level_4_result.clear()
        self.level_5_result.clear()


if __name__ == "__main__":
    pass
