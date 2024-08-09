import pytest
import importlib

from unittest.mock import patch

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from tests.agent.conftest import reload

import quark.agent.agentTools as agentTools


@pytest.fixture(scope="function", autouse=True)
def disableToolDecorator(missingLangchain):
    importlib.reload(agentTools)


@pytest.fixture(scope="session")
def quarkObject(SAMPLE_PATH_14d9f):
    rulePath = "quark/rules/sendLocation_SMS.json"
    rule = RuleObject(rulePath)
    quark = Quark(SAMPLE_PATH_14d9f)
    quark.run(rule)
    quark.show_summary_report(rule)

    return quark


def testImportAgentToolsWithoutLangChain():
    reload("quark.agent.agentTools")


def testInitRuleObject():
    rulePath = "quark/rules/sendLocation_SMS.json"

    agentTools.initRuleObject(rulePath)

    assert isinstance(agentTools.rule_checker, RuleObject)


def testInitQuarkObject(SAMPLE_PATH_14d9f):
    import quark.agent.agentTools as agentTools

    agentTools.initQuarkObject(SAMPLE_PATH_14d9f)

    assert isinstance(agentTools.quark, Quark)


def testRunQuarkAnalysis(SAMPLE_PATH_14d9f):
    rulePath = "quark/rules/sendLocation_SMS.json"

    with patch("quark.core.quark.Quark.run") as mockedRun:
        with patch(
            "quark.core.quark.Quark.show_summary_report"
        ) as mockedShowSummaryReport:

            agentTools.initRuleObject(rulePath)
            agentTools.initQuarkObject(SAMPLE_PATH_14d9f)
            agentTools.runQuarkAnalysis()

            assert mockedRun.assert_called_once
            assert mockedShowSummaryReport.assert_called_once


def testGetSummaryReportTable(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getSummaryReportTable()

    assert "Send Location via SMS" in result


def testGetAnalysisResultRisk(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getAnalysisResultRisk()

    assert "High Risk" in result


def testGetAnalysisResultScore(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getAnalysisResultScore()

    assert result == 4
