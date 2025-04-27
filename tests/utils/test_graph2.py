import os.path

import pytest
import requests
from pathvalidate import sanitize_filename

from quark.core.apkinfo import AndroguardImp as Apkinfo
from quark.utils.graph import call_graph


@pytest.fixture(scope="module")
def analysis_object(tmp_path_factory):
    APK_SOURCE = (
        "https://github.com/quark-engine/" "apk-samples/raw/master/test-samples/F84E990228E08B52CDB839FB10BA36DFC187945CE94D73EB64916D453D95DA57.apk"
    )
    APK_NAME = "F84E990228E08B52CDB839FB10BA36DFC187945CE94D73EB64916D453D95DA57.apk"

    # Download apk
    request = requests.get(APK_SOURCE, timeout=10)
    apk_file = tmp_path_factory.getbasetemp() / APK_NAME
    apk_file.write_bytes(request.content)
    analysis = Apkinfo(apk_file)

    yield analysis


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
        f"{parent_method.name}_{connect_method_1.name}"
        f"_{connect_method_2.name}"
    )
    expected_file_name = sanitize_filename(expected_file_name,
                                           replacement_text="_")
    expected_file_name = os.path.join("call_graph_image", expected_file_name)

    call_graph(call_graph_analysis)

    assert os.path.exists(expected_file_name)
