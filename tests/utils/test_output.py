import json
import os

import pytest
import requests
from quark.Objects.apkinfo import Apkinfo
from quark.Objects.quark import MAX_SEARCH_LAYER
from quark.utils.output import (
    get_rule_classification_data,
    output_parent_function_graph,
    output_parent_function_json,
    output_parent_function_table,
)


@pytest.fixture(scope="module")
def sample_apk():
    APK_SOURCE = (
        "https://github.com/quark-engine/"
        "apk-malware-samples/raw/master/14d9f1a92dd984d6040cc41ed06e273e.apk"
    )
    APK_NAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"

    request = requests.get(APK_SOURCE, allow_redirects=True)
    with open(APK_NAME, "wb") as file:
        file.write(request.content)

    yield APK_NAME

    os.remove(APK_NAME)


@pytest.fixture(scope="module")
def analysis_object(sample_apk):
    return Apkinfo(sample_apk)


@pytest.fixture(scope="module")
def analysis_element_1(analysis_object):
    parent = analysis_object.find_method(
        "Lcom/google/progress/Locate;",
        "getLocation",
        "()Ljava/lang/String;",
    )
    first_api = analysis_object.find_method(
        "Lorg/apache/http/HttpResponse;",
        "getEntity",
        "()Lorg/apache/http/HttpEntity;",
    )
    second_api = analysis_object.find_method(
        "Lorg/json/JSONObject;",
        "put",
        "(Ljava/lang/String; I)Lorg/json/JSONObject;",
    )

    return {
        "crime": "The Crime",
        "parent": parent,
        "first_call": first_api,
        "first_api": first_api,
        "second_call": second_api,
        "second_api": second_api,
    }


@pytest.fixture(scope="module")
def analysis_element_2(analysis_object):
    parent = analysis_object.find_method(
        "Lcom/google/progress/AndroidClientService;",
        "sendMessage",
        "()V",
    )
    first_api = analysis_object.find_method(
        "Lcom/google/progress/FileList;",
        "getInfo",
        "()Ljava/lang/String;",
    )
    second_api = analysis_object.find_method(
        "Lcom/google/progress/SMSHelper;",
        "sendSms",
        "(Ljava/lang/String; Ljava/lang/String;)I",
    )

    return {
        "crime": "Another Crime",
        "parent": parent,
        "first_call": first_api,
        "first_api": first_api,
        "second_call": second_api,
        "second_api": second_api,
    }


@pytest.fixture(scope="function")
def referenced_crime_list(analysis_element_1, analysis_element_2):
    return [analysis_element_1, analysis_element_2]


@pytest.fixture(scope="function")
def duplicate_crime_list(analysis_element_1):
    return [analysis_element_1, analysis_element_1]


@pytest.fixture(scope="module")
def sample_data_bundle(analysis_element_1, analysis_element_2):
    parent_function_1 = analysis_element_1["parent"]
    parent_function_2 = analysis_element_2["parent"]

    report_dict = {
        parent_function_1: {"The Crime"},
        parent_function_2: {"Another Crime"},
    }
    reference_dict = {
        parent_function_1: set(),
        parent_function_2: {parent_function_1},
    }
    return report_dict, reference_dict


def test_get_rule_classification_data_with_referenced_crime(
    referenced_crime_list,
):
    expected_parent_1 = referenced_crime_list[0]["parent"]
    expected_parent_2 = referenced_crime_list[1]["parent"]

    report_dict, reference_dict = get_rule_classification_data(
        referenced_crime_list, MAX_SEARCH_LAYER
    )

    assert report_dict.keys() == {expected_parent_1, expected_parent_2}
    assert report_dict[expected_parent_1] == {"The Crime"}
    assert report_dict[expected_parent_2] == {"Another Crime"}
    assert reference_dict.keys() == {expected_parent_1, expected_parent_2}
    assert reference_dict[expected_parent_1] == set()
    assert reference_dict[expected_parent_2] == {expected_parent_1}


def test_get_rule_classification_data_with_duplicate_crime(
    duplicate_crime_list,
):
    expected_parent = duplicate_crime_list[0]["parent"]

    report_dict, reference_dict = get_rule_classification_data(
        duplicate_crime_list, MAX_SEARCH_LAYER
    )

    assert set(report_dict.keys()) == {expected_parent}
    assert report_dict[expected_parent] == {"The Crime"}
    assert set(reference_dict.keys()) == {expected_parent}
    assert reference_dict[expected_parent] == set()


def test_output_parent_function_table_with_data_bundle(
    capsys, sample_data_bundle
):
    output_parent_function_table(sample_data_bundle)

    output = capsys.readouterr().out
    assert output.count("Lcom/google/progress/Locate;getLocation") == 2
    assert (
        output.count("Lcom/google/progress/AndroidClientService;sendMessage")
        == 1
    )
    assert output.count("Call Lcom/google/progress/Locate;getLocation") == 1
    assert output.count("The Crime") == 1
    assert output.count("Another Crime") == 1


def test_output_parent_function_json_with_sample_data_bundle(
    sample_data_bundle,
):
    output_parent_function_json(sample_data_bundle)

    with open("rules_classification.json", "r") as classification_report:
        report = json.load(classification_report)

        assert len(report["rules_classification"]) == 2

        first_item = report["rules_classification"][0]
        second_item = report["rules_classification"][1]
        if first_item["parent"] != "Lcom/google/progress/Locate;getLocation":
            first_item, second_item = second_item, first_item

        assert set(first_item["crime"]) == {"The Crime"}
        assert set(second_item["crime"]) == {
            "Call Lcom/google/progress/Locate;getLocation",
            "Another Crime",
        }

        assert (
            second_item["parent"]
            == "Lcom/google/progress/AndroidClientService;sendMessage"
        )


def test_output_parent_function_graph_with_sample_data_bundle(
    sample_data_bundle,
):
    expected_filename = "rules_classification"

    output_parent_function_graph(sample_data_bundle)

    assert os.path.exists(expected_filename)
