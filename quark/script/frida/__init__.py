# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import json
import re
import sys
from dataclasses import dataclass
from time import sleep
from typing import Any, Dict, List, Tuple, Union

import pkg_resources
from quark.utils.regex import URL_REGEX

import frida
from frida.core import Device
from frida.core import Session as FridaSession

MethodCallEvent = Dict[str, Union[List[str], str]]


class MethodCallEventDispatcher:
    def __init__(self, frida: FridaSession) -> None:
        self.frida = frida
        self.watchedMethods = {}

    @staticmethod
    def _getMethodIdentifier(targetMethod: str, paramType: str):
        return (targetMethod, paramType)

    def startWatchingMethodCall(
        self, targetMethod: str, methodParamTypes: str
    ) -> List[MethodCallEvent]:
        """Start tracking calls to the target method.

        :param targetMethod: the target API
        :param methodParamTypes: the parameter types of the target API
        :return: python list that holds calls to the target method
        """
        eventBuffer = []
        methodId = self._getMethodIdentifier(targetMethod, methodParamTypes)

        self.watchedMethods[methodId] = eventBuffer
        self.script.exports.watch_method_call(targetMethod, methodParamTypes)

        return eventBuffer

    def stopWatchingMethodCall(
        self, targetMethod: str, methodParamTypes: str
    ) -> None:
        """Stop tracking calls to the target method.

        :param targetMethod: the target API
        :param methodParamTypes: the parameter types of the target API
        """
        methodId = self._getMethodIdentifier(targetMethod, methodParamTypes)

        if methodId in self.watchedMethods:
            del self.watchedMethods[methodId]

    def handleCapturedEvent(self, eventWrapperFromFrida: dict, _) -> None:
        """Send the event captured by Frida to the corresponding
         buffers.

        :param eventWrapperFromFrida: python dict containing captured events
        """
        if eventWrapperFromFrida["type"] == "error":
            errorDescription = eventWrapperFromFrida["description"]
            print(errorDescription, file=sys.stderr)
            return

        methodCallEvent = json.loads(eventWrapperFromFrida["payload"])

        eventType = methodCallEvent.get("type", None)

        if eventType == "CallCaptured":
            methodId = tuple(methodCallEvent["identifier"][0:2])

            if methodId in self.watchedMethods:
                messageBuffer = self.watchedMethods[methodId]
                messageBuffer.append(methodCallEvent)

        elif eventType == "FailedToWatch":
            methodId = tuple(methodCallEvent["identifier"])
            self.watchedMethods.pop(methodId)


@functools.lru_cache
def _spawnApp(
    appPackageName: str, protocol="usb", **kwargs: Any
) -> Tuple[Device, FridaSession, int]:
    """Spawn the target APP with Frida

    :param appPackageName: the package name of the target APP
    :param protocol: string that holds the protocol to communicate with the
     Frida server, defaults to "usb"
    :return: tuple containing the device ID, the Frida instance and the process
     ID of the APP.
    """
    device = None
    if protocol == "usb":
        device = frida.get_usb_device(**kwargs)
    elif protocol == "local":
        device = frida.get_local_device(**kwargs)
    elif protocol == "remote":
        device = frida.get_remote_device(**kwargs)

    processId = device.spawn([appPackageName])
    session = device.attach(processId)

    return device, session, processId


@functools.lru_cache
def _injectAgent(frida: FridaSession) -> MethodCallEventDispatcher:
    """Inject a Frida agent to help track method calls.

    :param frida: Frida instance to be injected
    :return: dispatcher that stores the captured calls to the appropriate
     buffers
    """
    dispatcher = MethodCallEventDispatcher(frida)

    pathToFridaAgentSource = pkg_resources.resource_filename(
        "quark.script.frida", "agent.js"
    )

    with open(pathToFridaAgentSource, "r") as fridaAgentSource:
        fridaAgent = dispatcher.frida.create_script(fridaAgentSource.read())
        fridaAgent.on("message", dispatcher.handleCapturedEvent)
        fridaAgent.load()
        dispatcher.script = fridaAgent

    return dispatcher


@dataclass
class Behavior:
    _callEvent: MethodCallEvent

    def hasString(self, pattern: str, regex: bool = False) -> List[str]:
        """Check if the behavior contains strings

        :param pattern: string to be checked
        :param regex: True if the string is a regular expression, defaults to
         False
        :return: python list containing all matched strings
        """
        arguments = self.getParamValues()

        allMatchedStrings = set()
        for argument in arguments:
            if regex:
                matchedStrings = [
                    match.group(0) for match in re.finditer(pattern, argument)
                ]
                allMatchedStrings.update(matchedStrings)
            else:
                if pattern in argument:
                    return [pattern]

        return list(allMatchedStrings)

    def hasUrl(self) -> List[str]:
        """Check if the behavior contains urls.

        :return: python list containing all detected urls
        """
        return self.hasString(URL_REGEX, True)

    def getParamValues(self) -> List[str]:
        """Get parameter values from behavior.

        :return: python list containing parameter values
        """
        return self._callEvent["paramValues"]


@dataclass
class FridaResult:
    _eventBuffer: List[MethodCallEvent]

    @property
    def behaviorOccurList(self) -> List[Behavior]:
        """List that stores instances of detected behavior in different part of
         the target file.

        :return: detected behavior instance
        """
        return [Behavior(message) for message in self._eventBuffer]


def runFridaHook(
    apkPackageName: str,
    targetMethod: str,
    methodParamTypes: str,
    secondToWait: int = 10,
) -> FridaResult:
    """Track calls to the specified method for given seconds.

    :param apkPackageName: the package name of the target APP
    :param targetMethod: the target API
    :param methodParamTypes: string that holds the parameters used by the
     target API
    :param secondToWait: seconds to wait for method calls, defaults to 10
    :return: FridaResult instance
    """
    device, frida, appProcess = _spawnApp(apkPackageName)
    dispatcher = _injectAgent(frida)

    eventBuffer = dispatcher.startWatchingMethodCall(
        targetMethod, methodParamTypes
    )
    device.resume(appProcess)

    sleep(secondToWait)
    dispatcher.stopWatchingMethodCall(targetMethod, methodParamTypes)

    return FridaResult(eventBuffer)
