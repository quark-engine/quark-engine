import json
import os

import pytest
import requests
from androguard.misc import AnalyzeAPK
from quark.utils.output import (
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
def method_object(sample_apk):
    _, _, analysis_object = AnalyzeAPK(sample_apk)

    return next(
        analysis_object.find_methods(
            "Lcom/google/progress/Locate;",
            "getLocation",
            "\\(\\)Ljava/lang/String;",
        )
    )


@pytest.fixture(scope="function")
def one_crime_list(method_object):
    return [
        {"crime": "The Crime", "parent": method_object},
    ]


@pytest.fixture(scope="function")
def duplicate_crime_list(method_object):
    return [
        {"crime": "The Crime", "parent": method_object},
        {"crime": "The Crime", "parent": method_object},
        {"crime": "Another Crime", "parent": method_object},
    ]


def test_output_parent_function_table_with_one_crime(capsys, one_crime_list):
    output_parent_function_table(one_crime_list)

    # f"{item['parent'].class_name}{item['parent'].name}"
    output = capsys.readouterr().out
    assert output.count("Lcom/google/progress/Locate;getLocation") == 1
    assert output.count("The Crime") == 1


def test_output_parent_function_table_with_duplicated_description(
    capsys, duplicate_crime_list
):

    output_parent_function_table(duplicate_crime_list)

    output = capsys.readouterr().out
    assert output.count("Lcom/google/progress/Locate;getLocation") == 1
    assert output.count("The Crime") == 1
    assert output.count("Another Crime") == 1


def test_output_parent_function_json_with_one_crime(one_crime_list):
    output_parent_function_json(one_crime_list)

    with open("rules_classification.json", "r") as classification_report:
        report = json.load(classification_report)

        assert len(report["rules_classification"]) == 1
        assert (
            report["rules_classification"][0]["parent"]
            == "Lcom/google/progress/Locate;getLocation"
        )
