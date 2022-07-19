# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from unittest import TestCase
from unittest.mock import patch

from quark.core.struct.methodobject import MethodObject
from quark.script import Method
from quark.script.objection import Objection, convertMethodToString


def testCovertMethodToStringWithClasses():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name$subclass;",
            "method_name",
            "(Ljava/lang/String; Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name$subclass.method_name",
        "java.lang.String,java.lang.Object",
    )


def testCovertMethodToStringWithPrimitives():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;", "method_name", "(I [B J)V"
        ),
    )

    result = convertMethodToString(method)

    assert result == ("custom.class.name.method_name", "I,[B,J")


def testCovertMethodToStringWithArrays():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;",
            "method_name",
            "([Ljava/lang/String; [Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name.method_name",
        "[Ljava.lang.String;,[Ljava.lang.Object;",
    )


def testCovertMethodToStringWithArrayAndClass():
    method = Method(
        quarkResultInstance=None,
        methodObj=MethodObject(
            "Lcustom/class/name;",
            "method_name",
            "([Ljava/lang/String; Ljava/lang/Object;)V",
        ),
    )

    result = convertMethodToString(method)

    assert result == (
        "custom.class.name.method_name",
        "[Ljava.lang.String;,java.lang.Object",
    )


class TestObjection:
    @staticmethod
    def testHookMethodWithMethodObject():
        obj = Objection("127.0.0.1:8888")
        method = Method(
            None,
            MethodObject(
                "Lcom/google/progress/WifiCheckTask;",
                "checkWifiCanOrNotConnectServer",
                "([Ljava/lang/String;)Z",
            ),
        )

        with patch("requests.post") as mocked_post:
            obj.hookMethod(
                method, watchArgs=True, watchBacktrace=True, watchRet=True
            )

            expectedJson = {
                "pattern": (
                    "com.google.progress.WifiCheckTask"
                    ".checkWifiCanOrNotConnectServer"
                ),
                "overloadFilter": "[Ljava.lang.String;",
                "watchArgs": True,
                "watchBacktrace": True,
                "watchRet": True,
            }

            args, keyworkArgs = mocked_post.call_args_list[0]

            assert (
                "http://127.0.0.1:8888/rpc/invoke/androidHookingWatchMethod"
                in args
            )

            TestCase().assertDictEqual(keyworkArgs["json"], expectedJson)
            TestCase().assertDictEqual(
                keyworkArgs["headers"], {"Content-type": "application/json"}
            )
