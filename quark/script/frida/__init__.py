# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import json
import re
import sys
from dataclasses import dataclass
from time import sleep
from typing import Any, Dict, List, Tuple

import pkg_resources
from quark.script import Behavior
from quark.utils.regex import URL_REGEX

import frida
from frida.core import Device
from frida.core import Session as FridaSession


class MethodCallEventDispatcher:
    def __init__(self, frida: FridaSession) -> None:
        self.frida = frida
        self.watchedMethods = {}

    @staticmethod
    def _getMethodIdentifier(targetMethod: str, paramType: str):
        return (targetMethod, paramType)

    def startWatchingMethodCall(
        self, targetMethod: str, methodParamTypes: str
    ) -> List["Behavior"]:
        """Start tracking calls to the target method.

        :param targetMethod: the target API
        :param methodParamTypes: the parameter types of the target API
        :return: python list that holds calls to the target method
        """
        messageBuffer = []
        id = self._getMethodIdentifier(targetMethod, methodParamTypes)

        self.watchedMethods[id] = messageBuffer
        self.script.exports.watch_method_call(targetMethod, methodParamTypes)

        return messageBuffer

    def stopWatchingMethodCall(
        self, targetMethod: str, methodParamTypes: str
    ) -> None:
        """Stop tracking calls to the target method.

        :param targetMethod: the target API
        :param methodParamTypes: the parameter types of the target API
        """
        id = self._getMethodIdentifier(targetMethod, methodParamTypes)

        if id in self.watchedMethods:
            del self.watchedMethods[id]

    def receiveMessage(self, messageFromFridaAgent: dict, _) -> None:
        if messageFromFridaAgent["type"] == "error":
            errorDescription = messageFromFridaAgent["description"]
            print(errorDescription, file=sys.stderr)
            return

        receivedEvent = json.loads(messageFromFridaAgent["payload"])

        eventType = receivedEvent.get("type", None)

        if eventType == "CallCaptured":
            id = tuple(receivedEvent["identifier"][0:2])

            if id in self.watchedMethods:
                messageBuffer = self.watchedMethods[id]
                messageBuffer.append(receivedEvent)

        elif eventType == "FailedToWatch":
            id = tuple(receivedEvent["identifier"])
            self.watchedMethods.pop(id)


@functools.lru_cache
def _setupFrida(
    appPackageName: str, protocol="usb", **kwargs: Any
) -> Tuple[Device, FridaSession, int]:
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
    dispatcher = MethodCallEventDispatcher(frida)

    pathToFridaAgentSource = pkg_resources.resource_filename(
        "quark.script.frida", "agent.js"
    )

    with open(pathToFridaAgentSource, "r") as fridaAgentSource:
        fridaAgent = dispatcher.frida.create_script(fridaAgentSource.read())
        fridaAgent.on("message", dispatcher.receiveMessage)
        fridaAgent.load()
        dispatcher.script = fridaAgent

    return dispatcher


@dataclass
class Behavior:
    _message: Dict[str, str]

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
        return self._message["paramValues"]


@dataclass
class FridaResult:
    _messageBuffer: List[str]

    @property
    def behaviorOccurList(self) -> List[Behavior]:
        """List that stores instances of detected behavior in different part of
         the target file.

        :return: detected behavior instance
        """
        return [Behavior(message) for message in self._messageBuffer]


def runFridaHook(
    apkPackageName: str,
    targetMethod: str,
    methodParamTypes: str,
    secondToWait: int,
) -> FridaResult:
    """Track calls to the specified method for given seconds.

    :param apkPackageName: the target APK
    :param targetMethod: the target API
    :param methodParamTypes: string that holds the parameters used by the
     target API
    :param secondToWait: seconds to wait for method calls
    :return: FridaResult instance
    """
    device, frida, appProcess = _setupFrida(apkPackageName)
    dispatcher = _injectAgent(frida)

    buffer = dispatcher.startWatchingMethodCall(targetMethod, methodParamTypes)
    device.resume(appProcess)

    sleep(secondToWait)
    dispatcher.stopWatchingMethodCall(targetMethod, methodParamTypes)

    return FridaResult(buffer)
