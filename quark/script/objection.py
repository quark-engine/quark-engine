# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import re
from typing import Tuple, Union

import requests
from quark.script import Method


def convertMethodToString(method: Method):
    def converArgumentsToObjectionFormat(arguments: str):
        argList = arguments.split()
        argList = map(
            lambda a: a.replace("/", ".")
            if a.startswith("[L")
            else re.sub("(^L)|;", "", a).replace("/", "."),
            argList,
        )

        return ",".join(argList)

    str_mapping = {
        "class_name": method.class_name[1:-1].replace("/", "."),
        "method_name": method.name,
        "arguments": converArgumentsToObjectionFormat(
            method.descriptor[1: method.descriptor.index(")")]
        ),
    }
    return (
        "{class_name}.{method_name}".format_map(str_mapping),
        str_mapping["arguments"],
    )


class Objection:
    def __init__(self, host: str) -> None:
        """Create an instance for Objection (dynamic analysis tool).

        :param host: Monitoring IP:port
        """
        self.host = host

    def _sendRequest(
        self, rpcEndpoint: str, data: dict = None
    ) -> Tuple[int, dict]:
        url = f"http://{self.host}/rpc/invoke/{rpcEndpoint}"

        if data:
            response = requests.post(
                url, json=data, headers={"Content-type": "application/json"}
            )
        else:
            response = requests.get(url)

        return (response.status_code, response.json())

    def hookMethod(
        self,
        method: Union[Method, str],
        overloadFilter: str = "",
        watchArgs: bool = False,
        watchBacktrace: bool = False,
        watchRet: bool = False,
    ):
        """Hook the target method with Objection.

        :param method: the tagrget API
        :param overloadFilter: _description_, defaults to ""
        :param watchArgs: Return Args information if True, defaults to False
        :param watchBacktrace: Return backtrace information if True, defaults
         to False
        :param watchRet: Return the return information of the target API if
         True, defaults to False
        """

        # Convert Method object to a string
        if isinstance(method, Method):
            method, overloadFilter = convertMethodToString(method)

        ENDPOINT = "androidHookingWatchMethod"
        data = {
            "pattern": method,
            "overloadFilter": overloadFilter,
            "watchArgs": watchArgs,
            "watchBacktrace": watchBacktrace,
            "watchRet": watchRet,
        }

        self._sendRequest(ENDPOINT, data)
