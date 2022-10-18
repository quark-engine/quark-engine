# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
from os import PathLike
from os.path import abspath, isfile, join
from typing import Any, List, Tuple, Union

from quark.config import DIR_PATH as QUARK_RULE_PATH
from quark.core.analysis import QuarkAnalysis
from quark.core.interface.baseapkinfo import XMLElement
from quark.core.quark import Quark
from quark.core.struct.methodobject import MethodObject
from quark.core.struct.ruleobject import RuleObject as Rule
from quark.evaluator.pyeval import PyEval
from quark.utils.regex import URL_REGEX
from quark.utils.tools import (
    get_arguments_from_argument_str,
    get_parenthetic_contents,
)


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


class Activity:
    def __init__(self, xml: XMLElement) -> None:
        self.xml: XMLElement = xml

    def __str__(self) -> str:
        return self._getAttribute("name")

    def _getAttribute(
        self, attributeName: str, defaultValue: Any = None
    ) -> Any:
        realAttributeName = (
            f"{{http://schemas.android.com/apk/res/android}}{attributeName}"
        )
        return self.xml.get(realAttributeName, defaultValue)

    def hasIntentFilter(self) -> bool:
        """Check if the activity has an intent filter.

        :return: True/False
        """
        return self.xml.find("intent-filter") is not None

    def isExported(self) -> bool:
        """Check if the activity is exported.

        :return: True/False
        """
        exported = self._getAttribute("exported", self.hasIntentFilter())
        return exported


class Method:
    def __init__(
        self,
        quarkResultInstance: "QuarkResult" = None,
        methodObj: MethodObject = None,
        quark: "Quark" = None,
        behavior: "Behavior" = None,
        targetMethod: "Method" = None
    ) -> None:
        self.quark = quark
        self.quarkResult = quarkResultInstance
        self.innerObj = methodObj
        self.behavior = behavior
        self.targetMethod = targetMethod

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

    def getArguments(self) -> List[Any]:
        """Get arguments from method.

        :return: python list containing arguments
        """

        if self.behavior is None or self.quarkResult is None:

            usageTable = self.quark._evaluate_method(
                self.innerObj
            )

            register_usage_records = (
                c_func
                for table in usageTable
                for val_obj in table
                for c_func in val_obj.called_by_func
            )

            methodPattern = PyEval.get_method_pattern(
                self.targetMethod.innerObj.class_name,
                self.targetMethod.innerObj.name,
                self.targetMethod.innerObj.descriptor
            )

            matchedRecords = list(filter(
                lambda record: methodPattern in record,
                register_usage_records))

            argumentStr = max(matchedRecords, key=len)[:-1]
            filterStr = f"{self.targetMethod.innerObj.class_name}->" + \
                self.targetMethod.innerObj.name + \
                self.targetMethod.descriptor

            argumentStr = argumentStr.replace(filterStr, "")[1:]

            return get_arguments_from_argument_str(
                argumentStr, self.targetMethod.innerObj.descriptor
            )

        argumentsOfSecondAPI = self.behavior.getParamValues()

        if self == self.behavior.secondAPI:
            return self.behavior.getParamValues()
        else:
            methodPattern = PyEval.get_method_pattern(
                self.className, self.methodName, self.descriptor
            )

            argumentsOfFirstAPI = (
                get_parenthetic_contents(
                    argument, argument.find(methodPattern)
                )
                for argument in argumentsOfSecondAPI
                if methodPattern in argument
            )

            return get_arguments_from_argument_str(
                next(argumentsOfFirstAPI, ""), self.descriptor
            )

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

        self.methodCaller.behavior = self
        self.firstAPI.behavior = self
        self.secondAPI.behavior = self

    def hasString(self, pattern: str, isRegex=False) -> List[str]:
        """Check if the arguments of the two APIs contain the string.

        :param pattern: string that may appear in the arguments
        :param isRegex: consider the string as a regular expression if True,
         defaults to False
        :return: the matched string
        """
        usageTable = self.quarkResult.quark._evaluate_method(
            self.methodCaller.innerObj
        )

        result_generator = (
            self.quarkResult.quark.check_parameter_on_single_method(
                usage_table=usageTable,
                first_method=self.firstAPI.innerObj,
                second_method=self.secondAPI.innerObj,
                keyword_item_list=[(pattern,), (pattern,)],
                regex=isRegex,
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

    def getParamValues(self) -> List[Any]:
        """Get parameter values from behavior.

        :return: python list containing parameter values
        """
        allResult = self.hasString(".*", True)

        argumentStr = max(allResult, key=len)[1:-1]
        return get_arguments_from_argument_str(
            argumentStr, self.secondAPI.descriptor
        )

    def isArgFromMethod(self, targetMethod: List[str]) -> bool:
        """Check if there are any argument from the target method.

        :param targetMethod: python list contains class name, method name, and
         descriptor of target method
        :return: True/False
        """
        className, methodName, descriptor = targetMethod

        pattern = PyEval.get_method_pattern(className, methodName, descriptor)

        return bool(self.hasString(pattern))


class QuarkResult:
    def __init__(self, quark: Quark, ruleInstance: Rule) -> None:
        self.quark = quark
        self.quark.run(ruleInstance)
        self.rule = ruleInstance

        # Reset the Quark object
        self.innerObj = self.quark.quark_analysis
        self.quark.quark_analysis = QuarkAnalysis()

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

    def _wrapMethodObject(self, methodObj: MethodObject) -> Method:
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
        callerMethod: Union[List[str], Method],
        targetMethod: Union[List[str], Method],
    ) -> bool:
        """
        Check if target method is in caller method.

        :params callerMethod: python list or Method instance containing class
         name, method name and descriptor of caller method.
        :params targetMethod: python list or Method instance containing class
         name, method name and descriptor of target method.
        :return: True/False
        """

        def __convertMethodToListOfStr(method: Method) -> List[str]:
            return [method.className, method.methodName, method.descriptor]

        if isinstance(callerMethod, Method):
            callerMethod = __convertMethodToListOfStr(callerMethod)
        if isinstance(targetMethod, Method):
            targetMethod = __convertMethodToListOfStr(targetMethod)

        apkinfo = self.quark.apkinfo

        callerMethodObj = apkinfo.find_method(
            class_name=callerMethod[0],
            method_name=callerMethod[1],
            descriptor=callerMethod[2],
        )

        if not callerMethodObj:
            print("Caller method not Found!")
            raise ValueError

        callerMethodInstance = Method(self, callerMethodObj)

        for calleeMethod, _ in callerMethodInstance.getXrefTo():
            if (
                calleeMethod.innerObj.class_name == targetMethod[0]
                and calleeMethod.innerObj.name == targetMethod[1]
                and calleeMethod.innerObj.descriptor == targetMethod[2]
            ):
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


def getActivities(samplePath: PathLike) -> List[Activity]:
    """Get activities from a target sample.

    :param samplePath: target file
    :return: python list containing activities
    """
    quark = _getQuark(samplePath)
    apkinfo = quark.apkinfo

    return [Activity(xml) for xml in apkinfo.activities]


def findMethodInAPK(
    samplePath: PathLike,
    targetMethod: Union[List[str], Method]
) -> Method:
    """Find the target method in APK.

    :param samplePath: target file
    :param targetMethod: python list contains class name,
                         method name, and descriptor of target method
    :return: python list contains caller methods
    """

    def _wrapMethodObject(
        quark: Quark,
        methodObj: MethodObject,
        targetMethod: Method
    ) -> Method:
        if methodObj:
            return Method(
                quark=quark,
                methodObj=methodObj,
                targetMethod=targetMethod)
        else:
            return None

    quark = _getQuark(samplePath)
    method = quark.apkinfo.find_method(
        class_name=targetMethod[0],
        method_name=targetMethod[1],
        descriptor=targetMethod[2]
    )

    methodInstance = Method(methodObj=method)

    caller_set = quark.apkinfo.upperfunc(method)

    return [_wrapMethodObject(
            quark, caller, methodInstance
            ) for caller in list(caller_set)]
