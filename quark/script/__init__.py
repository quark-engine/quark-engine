# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
from os import PathLike
from os.path import abspath, isfile, join
from typing import Any, List, Tuple, Union

from quark.config import DIR_PATH as QUARK_RULE_PATH
from quark.core.analysis import QuarkAnalysis
from quark.core.quark import Quark
from quark.core.struct.methodobject import MethodObject
from quark.core.struct.ruleobject import RuleObject as Rule
from quark.utils.regex import URL_REGEX


@functools.lru_cache
def _getQuark(apk: PathLike) -> Quark:
    return Quark(apk)


class Ruleset:
    def __init__(self, ruleFolder: PathLike) -> None:
        self.ruleFolder = ruleFolder

        # Apply cache
        self._loadRule = functools.lru_cache()(self._loadRuleWithoutCache)

    def __getitem__(self, key: str) -> Rule:
        return self._loadRule(key)

    def _loadRuleWithoutCache(self, key: str):
        absoluteRulePath = abspath(join(self.ruleFolder, key))

        if isfile(absoluteRulePath) and absoluteRulePath.endswith(".json"):
            return Rule(absoluteRulePath)
        else:
            raise KeyError(f"Unable to find file {absoluteRulePath}")


class DefaultRuleset(Ruleset):
    def __getitem__(self, key: Union[str, int]) -> Rule:
        return super().__getitem__(f"{key:05}.json")


DEFAULT_RULESET = DefaultRuleset(join(QUARK_RULE_PATH, "rules"))


class Method:
    def __init__(
        self, quarkResultInstance: "QuarkResult", methodObj: MethodObject
    ) -> None:
        self.quarkResult = quarkResultInstance
        self.innerObj = methodObj

    def __getattr__(self, name) -> Any:
        return getattr(self.innerObj, name)

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Method):
            return __o.innerObj == self.innerObj

        return False

    def getXrefTo(self) -> List[Tuple["Method", int]]:
        """Find out who this method called.

        :return: python list containing tuples (callee methods, index)
        """
        return self.quarkResult.getMethodXrefTo(self)

    def getXrefFrom(self) -> List["Method"]:
        """Find out who call this method.

        :return: python list containing caller methods
        """
        return self.quarkResult.getMethodXrefFrom(self)

    @property
    def fullName(self) -> str:
        """Show the name of the method.

        :return: the name of the method
        """
        return self.innerObj.full_name

    @property
    def className(self) -> str:
        """Show the class name of the method.

        :return: the string of the method class name
        """
        return self.innerObj.class_name

    @property
    def methodName(self) -> str:
        """Show the method name of the method.

        :return: the string of the method name
        """
        return self.innerObj.name

    @property
    def descriptor(self) -> str:
        """Show the descriptor of the method.

        :return: the string of the method descriptor
        """
        return self.innerObj.descriptor


class Behavior:
    def __init__(
        self,
        quarkResultInstance: "QuarkResult",
        methodCaller: Method,
        firstAPI: Method,
        secondAPI: Method,
    ) -> None:
        self.quarkResult = quarkResultInstance
        self.methodCaller = methodCaller
        self.firstAPI = firstAPI
        self.secondAPI = secondAPI

    def hasString(self, pattern: str, regex=False) -> List[str]:
        usageTable = self.quarkResult.quark._evaluate_method(
            self.methodCaller.innerObj
        )

        result_generator = (
            self.quarkResult.quark.check_parameter_on_single_method(
                usage_table=usageTable,
                first_method=self.firstAPI.innerObj,
                second_method=self.secondAPI.innerObj,
                keyword_item_list=[(pattern,), (pattern,)],
                regex=regex,
            )
        )

        found_keywords = {
            keyword
            for _, keyword_list in result_generator
            for keyword in keyword_list
        }

        return list(found_keywords)

    def hasUrl(self) -> List[str]:
        """Check if the behavior contains urls.

        :return: python list containing all detected urls
        """
        return self.hasString(URL_REGEX, True)

    def getParamValues(self) -> List[str]:
        """Get parameter values from behavior.

        :return: python list containing parameter values
        """
        allResult = self.hasString(".*", True)

        paramValues = []
        for result in allResult:
            if result[0] == "(" and result[-1] == ")" and \
                    self.firstAPI.innerObj.class_name in result and \
                    self.secondAPI.innerObj.class_name in result:

                paramValues = result[1:-1].split(",")[1:]

        return paramValues


class QuarkResult:
    def __init__(self, quark: Quark, ruleInstance: Rule) -> None:
        self.quark = quark
        self.quark.run(ruleInstance)
        self.rule = ruleInstance

        # Reset the Quark object
        self.innerObj = self.quark.quark_analysis
        self.quark.quark_analysis = QuarkAnalysis()

        # Apply cache
        self._wrapMethodObject = functools.lru_cache()(
            self._wrapMethodObjectWithoutCache
        )

    @functools.cached_property
    def behaviorOccurList(self):
        """List that stores instances of detected behavior in different part of
         the target file.

        :return: detected behavior instance
        """
        occurList = [
            Behavior(
                quarkResultInstance=self,
                methodCaller=self._wrapMethodObject(
                    call_graph_analysis["parent"]
                ),
                firstAPI=self._wrapMethodObject(
                    call_graph_analysis["first_call"]
                ),
                secondAPI=self._wrapMethodObject(
                    call_graph_analysis["second_call"]
                ),
            )
            for call_graph_analysis in self.innerObj.call_graph_analysis_list
        ]
        return occurList

    def getMethodXrefTo(self, method: Method) -> List[Tuple[Method, int]]:
        apkinfo = self.quark.apkinfo
        methodObj = method.innerObj

        callee_info = [
            (self._wrapMethodObject(callee), offset)
            for callee, offset in list(apkinfo.lowerfunc(methodObj))
        ]
        return callee_info

    def getMethodXrefFrom(self, method: Method) -> List[Method]:
        apkinfo = self.quark.apkinfo
        methodObj = method.innerObj

        caller_set = apkinfo.upperfunc(methodObj)
        return [self._wrapMethodObject(caller) for caller in list(caller_set)]

    def _wrapMethodObjectWithoutCache(self, methodObj: MethodObject) -> Method:
        if methodObj:
            return Method(self, methodObj)
        else:
            return None

    def getAllStrings(self) -> List[str]:
        """
        List all strings inside the target APK.

        :return: python list containing all defined strings.
        """
        apkinfo = self.quark.apkinfo
        return apkinfo.get_strings()

    def findMethodInCaller(
        self,
        callerMethod: List[str],
        targetMethod: List[str]
    ) -> bool:
        """
        Check if target method is in caller method.

        :params callerMethod: python list contains class name,
        method name and descriptor of caller method.
        :params targetMethod: python list contains class name,
        method name and descriptor of target method.
        :return: True/False
        """

        apkinfo = self.quark.apkinfo

        callerMethodObj = apkinfo.find_method(
            class_name=callerMethod[0],
            method_name=callerMethod[1],
            descriptor=callerMethod[2])

        if not callerMethodObj:
            print("Caller method not Found!")
            raise ValueError

        callerMethodInstance = Method(self, callerMethodObj)

        for calleeMethod, _ in callerMethodInstance.getXrefTo():
            if calleeMethod.innerObj.class_name == targetMethod[0] and \
                    calleeMethod.innerObj.name == targetMethod[1] and \
                    calleeMethod.innerObj.descriptor == targetMethod[2]:
                return True
        return False


def runQuarkAnalysis(samplePath: PathLike, ruleInstance: Rule) -> QuarkResult:
    """Given detection rule and target sample, this instance runs the basic
     Quark.

    :param samplePath: Target file
    :param ruleInstance: Quark rule object
    :return: QuarkResult instance
    """
    quark = _getQuark(samplePath)
    analysis = QuarkResult(quark, ruleInstance)

    return analysis
