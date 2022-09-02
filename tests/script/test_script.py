# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os

import pytest
import requests
from quark.core.struct.methodobject import MethodObject
from quark.script import DefaultRuleset, Method, Ruleset, runQuarkAnalysis

SAMPLE_SOURCE_URL = (
    "https://github.com/quark-engine/apk-malware-samples"
    "/raw/master/14d9f1a92dd984d6040cc41ed06e273e.apk"
)
SAMPLE_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"

RULE_FOLDER_PATH = "tests/script/rules"
RULE_FILENAME = "00068.json"
RULE_PATH = os.path.join(RULE_FOLDER_PATH, RULE_FILENAME)


@pytest.fixture(scope="session")
def SAMPLE_PATH(tmp_path_factory: pytest.TempPathFactory) -> str:
    folder = os.path.splitext(os.path.basename(__file__))[0]
    folder = tmp_path_factory.mktemp(folder)

    sample_path = folder / SAMPLE_FILENAME

    response = requests.get(SAMPLE_SOURCE_URL, allow_redirects=True)
    file = open(sample_path, "wb")
    file.write(response.content)
    file.close()

    return str(sample_path)


@pytest.fixture(scope="class")
def QUARK_ANALYSIS_RESULT(SAMPLE_PATH):
    ruleset = Ruleset(RULE_FOLDER_PATH)
    return runQuarkAnalysis(SAMPLE_PATH, ruleset[RULE_FILENAME])


class TestRuleset:
    @staticmethod
    def testInitWithFolder():
        _ = Ruleset(RULE_FOLDER_PATH)

    @staticmethod
    def testGetExistentRule():
        ruleset = Ruleset(RULE_FOLDER_PATH)

        rule = ruleset[RULE_FILENAME]

        assert rule.crime == "Executes the specified string Linux command"

    @staticmethod
    def testGetNonexistentRule():
        NONEXISTENT_RULE = "NONEXISTENT_RULE.json"
        ruleset = Ruleset(RULE_FOLDER_PATH)

        with pytest.raises(KeyError):
            _ = ruleset[NONEXISTENT_RULE]


class TestDefaultRuleset:
    @staticmethod
    def testGetExistentRuleByNumber():
        ruleset = DefaultRuleset(RULE_FOLDER_PATH)

        rule = ruleset[68]

        assert rule.crime == "Executes the specified string Linux command"

    @staticmethod
    def testGetNonexistentRuleByNumber():
        ruleset = DefaultRuleset(RULE_FOLDER_PATH)

        with pytest.raises(KeyError):
            _ = ruleset[1]


class TestMethod:
    @staticmethod
    def testInit(QUARK_ANALYSIS_RESULT):
        methodObj = MethodObject(
            class_name="Lcom/google/progress/WifiCheckTask;",
            name="checkWifiCanOrNotConnectServer",
            descriptor="()Z",
        )

        method = Method(QUARK_ANALYSIS_RESULT, methodObj)

        assert (
            method.fullName
            == "Lcom/google/progress/WifiCheckTask;"
            " checkWifiCanOrNotConnectServer ()Z"
        )

    @staticmethod
    def testGetXrefTo(QUARK_ANALYSIS_RESULT):
        methodObj = QUARK_ANALYSIS_RESULT.quark.apkinfo.find_method(
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "()Z",
        )
        method = Method(QUARK_ANALYSIS_RESULT, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT,
            MethodObject(
                "Landroid/util/Log;",
                "e",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            ),
        )
        expectedOffset = 116

        callee_list = method.getXrefTo()

        assert (expectedMethod, expectedOffset) in callee_list

    @staticmethod
    def testGetXrefFrom(QUARK_ANALYSIS_RESULT):
        methodObj = QUARK_ANALYSIS_RESULT.quark.apkinfo.find_method(
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "([Ljava/lang/String;)Z",
        )
        method = Method(QUARK_ANALYSIS_RESULT, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT,
            MethodObject("Lcom/google/progress/WifiCheckTask;", "test", "()V"),
        )

        caller_list = method.getXrefFrom()

        assert expectedMethod in caller_list


class TestBehavior:
    @staticmethod
    def testHasString(QUARK_ANALYSIS_RESULT):
        behaviorOccurList = QUARK_ANALYSIS_RESULT.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        result = behavior.hasString("ping")

        assert result

    @staticmethod
    def testHasUrl(QUARK_ANALYSIS_RESULT):
        behaviorOccurList = QUARK_ANALYSIS_RESULT.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        result = behavior.hasUrl()

        assert "www.baidu.com" in result

    @staticmethod
    def testGetParamValues(QUARK_ANALYSIS_RESULT):
        behaviorOccurList = QUARK_ANALYSIS_RESULT.behaviorOccurList
        behavior = next(
            filter(
                lambda b: "checkWifiCanOrNotConnectServer"
                in b.methodCaller.fullName,
                behaviorOccurList,
            )
        )

        assert behavior.getParamValues()[0] == "ping www.baidu.com"


class TestQuarkReuslt:
    @staticmethod
    def testMethodGetXrefTo(QUARK_ANALYSIS_RESULT):
        methodObj = QUARK_ANALYSIS_RESULT.quark.apkinfo.find_method(
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "()Z",
        )
        method = Method(QUARK_ANALYSIS_RESULT, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT,
            MethodObject(
                "Landroid/util/Log;",
                "e",
                "(Ljava/lang/String; Ljava/lang/String;)I",
            ),
        )
        expectedOffset = 116

        callee_list = QUARK_ANALYSIS_RESULT.getMethodXrefTo(method)

        assert (expectedMethod, expectedOffset) in callee_list

    @staticmethod
    def testMethodGetXrefFrom(QUARK_ANALYSIS_RESULT):
        methodObj = QUARK_ANALYSIS_RESULT.quark.apkinfo.find_method(
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "([Ljava/lang/String;)Z",
        )
        method = Method(QUARK_ANALYSIS_RESULT, methodObj)

        expectedMethod = Method(
            QUARK_ANALYSIS_RESULT,
            MethodObject("Lcom/google/progress/WifiCheckTask;", "test", "()V"),
        )

        caller_list = QUARK_ANALYSIS_RESULT.getMethodXrefFrom(method)

        assert expectedMethod in caller_list

    @staticmethod
    def testgetAllStrings(QUARK_ANALYSIS_RESULT):
        assert len(QUARK_ANALYSIS_RESULT.getAllStrings()) == 1005

    @staticmethod
    def testfindMethodInCaller(QUARK_ANALYSIS_RESULT):
        callerMethod = [
            "Lcom/google/progress/WifiCheckTask;",
            "checkWifiCanOrNotConnectServer",
            "([Ljava/lang/String;)Z",
        ]
        targetMethod = [
            "Landroid/util/Log;",
            "e",
            "(Ljava/lang/String; Ljava/lang/String;)I",
        ]

        assert QUARK_ANALYSIS_RESULT.findMethodInCaller(
            callerMethod, targetMethod)


def testRunQuarkAnalysis(SAMPLE_PATH):
    ruleset = Ruleset(RULE_FOLDER_PATH)
    ruleObj = ruleset[RULE_FILENAME]

    analysisResult = runQuarkAnalysis(SAMPLE_PATH, ruleObj)

    assert len(analysisResult.behaviorOccurList) == 1
