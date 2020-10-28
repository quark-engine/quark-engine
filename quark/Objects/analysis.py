from dataclasses import dataclass, field
from typing import Any
from prettytable import PrettyTable


def init_pretty_table():
    # Pretty Table Output
    tb = PrettyTable()
    tb.field_names = ["Rule", "Confidence", "Score", "Weight"]
    tb.align = "l"
    return tb


@dataclass()
class QuarkAnalysis:
    crime_description: str = ""
    first_api: Any = None
    second_api: Any = None
    level_1_result: list = field(default_factory=list)
    level_2_result: list = field(default_factory=list)
    level_3_result: list = field(default_factory=list)
    level_4_result: list = field(default_factory=list)
    level_5_result: list = field(default_factory=list)
    # Json report
    json_report: list = field(default_factory=list)
    # Sum of the each weight
    weight_sum: int = 0
    # Sum of the each rule
    score_sum: int = 0
    summary_report_table: PrettyTable = field(default_factory=init_pretty_table)
    # Call graph analysis
    call_graph_analysis_list: list = field(default_factory=list)

    def clean_result(self):
        self.level_1_result.clear()
        self.level_2_result.clear()
        self.level_3_result.clear()
        self.level_4_result.clear()
        self.level_5_result.clear()


if __name__ == "__main__":
    pass
