# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from quark.core.struct.ruleobject import RuleObject
from quark.utils.weight import Weight
from quark.core.quark import Quark
from quark.utils import colors

# Import the optional dependency, langchain
try:
    from langchain.agents import tool
except ModuleNotFoundError as e:
    # Create a fake tool in case langchain is not installed.
    def tool(func):
        return func


rule_checker = None
quark = None


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
    quark.run(rule_checker)
    quark.show_summary_report(rule_checker)
    return "Successfully run Quark analysis"


@tool
def getSummaryReportTable():
    """
    Get the summary report table from the Quark analysis result.
    """
    summaryReport = quark.quark_analysis.summary_report_table.get_string()

    return summaryReport


@tool
def getAnalysisResultRisk():
    """
    Get the risk from the Quark analysis result.
    """
    weight = Weight(
        quark.quark_analysis.score_sum, quark.quark_analysis.weight_sum
    )

    return weight.calculate()


@tool
def getAnalysisResultScore():
    """
    Get the score from the Quark analysis result.
    """
    return quark.quark_analysis.score_sum


@tool
def colorizeInYellow(text: str) -> str:
    """Colorize text in yellow.

    :param text: a text
    :return: the text in yellow
    """

    return colors.yellow(text)


@tool
def colorizeInCyan(text: str) -> str:
    """Colorize text in cyan.

    :param text: a text
    :return: the text in cyan
    """

    return colors.cyan(text)


@tool
def colorizeInGreen(text: str) -> str:
    """Colorize text in green.

    :param text: a text
    :return: the text in green
    """

    return colors.green(text)


@tool
def colorizeInRed(text: str) -> str:
    """Colorize text in red.

    :param text: a text
    :return: the text in red
    """

    return colors.red(text)


agentTools = [
    initRuleObject,
    initQuarkObject,
    runQuarkAnalysis,
    getSummaryReportTable,
    getAnalysisResultRisk,
    getAnalysisResultScore,
    colorizeInYellow,
    colorizeInCyan,
    colorizeInGreen,
    colorizeInRed,
]
