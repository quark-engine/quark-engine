import os.path

import pytest
import requests

from quark.core.apkinfo import AndroguardImp as Apkinfo
from quark.utils.graph import call_graph, wrapper_lookup


@pytest.fixture(scope="module")
def analysis_object(tmp_path_factory):
    APK_SOURCE = (
        "https://github.com/quark-engine/" "apk-samples/raw/master/malware-samples/Ahmyth.apk"
    )
    APK_NAME = "Ahmyth.apk"

    # Download apk
    request = requests.get(APK_SOURCE)
    apk_file = tmp_path_factory.getbasetemp() / APK_NAME
    apk_file.write_bytes(request.content)
    analysis = Apkinfo(apk_file)

    yield analysis


@pytest.fixture(scope="function")
def parent_method(analysis_object):
    return analysis_object.find_method(
        "Lahmyth/mine/king/ahmyth/ConnectionManager;",
        "sendReq",
        "()V",
    )[0]


@pytest.fixture(scope="function")
def connect_method_1(analysis_object):
    return analysis_object.find_method(
        "Lio/socket/client/Socket;",
        "connect",
        "()Lio/socket/client/Socket;",
    )[0]


@pytest.fixture(scope="function")
def connect_method_2(analysis_object):
    return analysis_object.find_method(
        "Lahmyth/mine/king/ahmyth/ConnectionManager$1;",
        "<init>",
        "()V",
    )[0]


@pytest.fixture(scope="function")
def leaf_method_1(analysis_object):
    return analysis_object.find_method(
        "Lio/socket/client/Socket;",
        "open",
        "()Lio/socket/client/Socket;",
    )[0]


@pytest.fixture(scope="function")
def leaf_method_2(analysis_object):
    return analysis_object.find_method(
        "Ljava/lang/Object;",
        "<init>",
        "()V",
    )[0]


def test_wrapper_lookup_with_result(
    analysis_object, parent_method, connect_method_1, leaf_method_1
):
    path = wrapper_lookup(analysis_object, parent_method, leaf_method_1)

    assert path == [connect_method_1]


def test_wrapper_lookup_with_no_result(analysis_object, leaf_method_1, parent_method):
    path = wrapper_lookup(analysis_object, leaf_method_1, parent_method)

    assert path == []


def test_call_graph(
    parent_method,
    analysis_object,
    connect_method_1,
    connect_method_2,
    leaf_method_1,
    leaf_method_2,
):
    call_graph_analysis = {
        "parent": parent_method,
        "apkinfo": analysis_object,
        "first_call": connect_method_1,
        "second_call": connect_method_2,
        "first_api": leaf_method_1,
        "second_api": leaf_method_2,
        "crime": "For test only.",
    }
    expected_file_name = (
        f"call_graph_image/{parent_method.name}_{connect_method_1.name}"
        f"_{connect_method_2.name}"
    )

    call_graph(call_graph_analysis)

    assert os.path.exists(expected_file_name)
