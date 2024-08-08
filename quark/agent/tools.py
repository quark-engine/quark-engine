# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from quark.core.struct.ruleobject import RuleObject
from quark.utils.weight import Weight
from quark.core.quark import Quark

# Import the optional dependency, langchain
try:
    from langchain.agents import tool
except ModuleNotFoundError as e:
    # Create a fake tool in case langchain is not installed.
    def tool(func):
        return func


@tool
def initRuleObject(rule_path: str):
    """
    Initialize a rule from the rule path.
    """
    global rule_checker

    rule_checker = RuleObject(rule_path)

    return "Rule initialized successfully"


@tool
def initQuarkObject(apk_path: str):
    """
    Init Quark using the apk path.
    """
    global quark

    quark_lib = "androguard"
    quark = Quark(apk_path, core_library=quark_lib)

    return "Quark initialized successfully"


@tool
def runQuarkAnalysis():
    """
    Run Quark analysis with a rule.
    """
    global quark
    global rule_checker

    quark.run(rule_checker)
    quark.show_summary_report(rule_checker)  # TODO - Refactor this API.
    return "Successfully run Quark analysis"


@tool
def getSummaryReportTable():
    """
    Get the summary report table from the Quark analysis result.
    """
    global quark
    global rule_checker

    summaryReport = quark.quark_analysis.summary_report_table.get_string()

    return summaryReport


@tool
def getAnalysisResultRisk():
    """
    Get the risk from the Quark analysis result.
    """

    global quark
    weight = Weight(
        quark.quark_analysis.score_sum, quark.quark_analysis.weight_sum
    )

    return weight.calculate()


@tool
def getAnalysisResultScore():
    """
    Get the score from the Quark analysis result.
    """

    global quark

    return quark.quark_analysis.score_sum


agentTools = [
    initRuleObject,
    initQuarkObject,
    runQuarkAnalysis,
    getSummaryReportTable,
    getAnalysisResultRisk,
    getAnalysisResultScore,
]
