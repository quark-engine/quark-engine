# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
import json
from unittest.mock import Mock, patch

from pytest import fixture
from quark.script.frida import (
    Behavior,
    FridaResult,
    MethodCallEventDispatcher,
    runFridaHook,
)


@fixture(scope="function")
def dispatcherThatHooksOneMethod():
    dispatcher = MethodCallEventDispatcher(None)
    dispatcher.script = Mock()

    targetMethod = (
        "com.google.progress.WifiCheckTask.checkWifiCanOrNotConnectServer"
    )
    methodParamTypes = "java.lang.String"

    buffer = dispatcher.startWatchingMethodCall(targetMethod, methodParamTypes)

    return dispatcher, targetMethod, methodParamTypes, buffer


@fixture(scope="function")
def methodCallMessages():
    return [
        {
            "type": "CallCaptured",
            "identifier": [
                (
                    "com.google.progress.WifiCheckTask"
                    ".checkWifiCanOrNotConnectServer"
                ),
                "java.lang.String",
                "V",
            ],
            "paramValues": [
                "SimpleString",
                "https://github.com/quark-engine/",
            ],
        }
    ]


class TestMethodCallEventDispatcher:
    @staticmethod
    def testStartWatchingMethodCallSuccess(dispatcherThatHooksOneMethod):
        (
            dispatcher,
            targetMethod,
            methodParamTypes,
            _,
        ) = dispatcherThatHooksOneMethod
        mockedFridaAgentAPI = dispatcher.script.exports.watch_method_call

        assert (
            dispatcher._getMethodIdentifier(targetMethod, methodParamTypes)
            in dispatcher.watchedMethods
        )
        mockedFridaAgentAPI.assert_called_once_with(
            targetMethod, methodParamTypes
        )

    @staticmethod
    def testStartWatchingMethodFailed(dispatcherThatHooksOneMethod):
        (
            dispatcher,
            targetMethod,
            methodParamTypes,
            _,
        ) = dispatcherThatHooksOneMethod

        failedToWatchMessage = {
            "type": "send",
            "payload": json.dumps(
                {
                    "type": "FailedToWatch",
                    "identifier": [targetMethod, methodParamTypes],
                }
            ),
        }

        dispatcher.receiveMessage(failedToWatchMessage, None)

        assert (
            dispatcher._getMethodIdentifier(targetMethod, methodParamTypes)
            not in dispatcher.watchedMethods
        )

    @staticmethod
    def testStopWatchingMethodCallSuccess(dispatcherThatHooksOneMethod):
        (
            dispatcher,
            targetMethod,
            methodParamTypes,
            _,
        ) = dispatcherThatHooksOneMethod

        dispatcher.stopWatchingMethodCall(targetMethod, methodParamTypes)

        assert (
            dispatcher._getMethodIdentifier(targetMethod, methodParamTypes)
            not in dispatcher.watchedMethods
        )

    @staticmethod
    def testStopWatchingMethodCallFailed(dispatcherThatHooksOneMethod):
        (
            dispatcher,
            targetMethod,
            methodParamTypes,
            _,
        ) = dispatcherThatHooksOneMethod

        dispatcher.stopWatchingMethodCall(targetMethod, methodParamTypes)
        dispatcher.stopWatchingMethodCall(targetMethod, methodParamTypes)

        assert (
            dispatcher._getMethodIdentifier(targetMethod, methodParamTypes)
            not in dispatcher.watchedMethods
        )

    @staticmethod
    def testDispatchCallMessage(dispatcherThatHooksOneMethod):
        (
            dispatcher,
            targetMethod,
            paramTypes,
            buffer,
        ) = dispatcherThatHooksOneMethod

        expectedEvent = {
            "type": "CallCaptured",
            "identifier": [targetMethod, paramTypes, "V"],
            "paramValues": ["param1", "param2"],
        }

        callMessage = {
            "type": "send",
            "payload": json.dumps(expectedEvent),
        }

        dispatcher.receiveMessage(callMessage, None)

        assert expectedEvent in buffer

    @staticmethod
    def testDispatchErrorMessage(dispatcherThatHooksOneMethod, capsys):
        dispatcher = dispatcherThatHooksOneMethod[0]

        errorMessage = {"type": "error", "description": "Any description."}

        dispatcher.receiveMessage(errorMessage, None)

        captured = capsys.readouterr()

        assert errorMessage["description"] in captured.err


class TestBehavior:
    @staticmethod
    def testHasString(methodCallMessages):
        behavior = Behavior(methodCallMessages[0])  # nosec E1120
        capturedStrings = behavior.hasString("SimpleString")
        assert capturedStrings == ["SimpleString"]

    @staticmethod
    def testHasUrl(methodCallMessages):
        behavior = Behavior(methodCallMessages[0])
        capturedUrls = behavior.hasUrl()
        assert capturedUrls == ["https://github.com/quark-engine/"]

    @staticmethod
    def testGetParamValues(methodCallMessages):
        behavior = Behavior(methodCallMessages[0])
        capturedArguments = behavior.getParamValues()
        assert capturedArguments == [
            "SimpleString",
            "https://github.com/quark-engine/",
        ]


class TestFridaResult:
    @staticmethod
    def testGetBehaviorOccurList(methodCallMessages):
        fridaResult = FridaResult(methodCallMessages)
        behaviorOccurList = fridaResult.behaviorOccurList
        assert len(behaviorOccurList) == 1


def testFridaHook(methodCallMessages):
    mockedSession = Mock()
    mockedSession.create_script.return_value = Mock()

    mockedDevice = Mock()
    mockedDevice.spawn.return_value = 1
    mockedDevice.attach.return_value = mockedSession

    appPackageName = "appName"
    targetMethod = "targetMethod"
    paramTypes = "paramType1,paramType2"

    with patch("frida.get_usb_device", return_value=mockedDevice) as _:
        with patch(
            (
                "quark.script.frida.MethodCallEventDispatcher"
                ".startWatchingMethodCall"
            ),
            return_value=methodCallMessages,
        ) as _:
            fridaResult = runFridaHook(
                appPackageName, targetMethod, paramTypes, 10
            )

            assert len(fridaResult.behaviorOccurList) == 1
