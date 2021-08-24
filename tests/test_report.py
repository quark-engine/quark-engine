import os
import os.path
import zipfile
from unittest.mock import patch

import pytest
import requests

from quark.report import Report


@pytest.fixture(scope="function")
def invalid_file(tempfile):
    tempfile.write("Text in file.")

    yield tempfile


@pytest.fixture(scope="module")
def sample_apk_file():
    APK_SOURCE = (
        "https://github.com/quark-engine/" "apk-malware-samples/raw/master/Ahmyth.apk"
    )
    APK_NAME = "Ahmyth.apk"

    # Download apk
    request = requests.get(APK_SOURCE)
    with open(APK_NAME, "wb") as apk_file:
        apk_file.write(request.content)

    yield APK_NAME

    os.remove(APK_NAME)


@pytest.fixture(scope="module")
def sample_dex_file(sample_apk_file):
    DEX_NAME = "classes.dex"

    with zipfile.ZipFile(sample_apk_file, "r") as zip:
        zip.extract(DEX_NAME)

    yield DEX_NAME

    os.remove(DEX_NAME)


@pytest.fixture(scope="module")
def sample_rule_file():
    return "quark/rules/sendLocation_SMS.json"


@pytest.fixture(scope="module")
def sample_rule_directory():
    return "quark/rules"


@pytest.fixture(scope="function")
def sample_report():
    report = Report()

    yield report

    del report


class TestReport:
    def test_analysis_with_both_invalid_types(self, sample_report):
        with pytest.raises(TypeError):
            sample_report.analysis(None, None)

    @pytest.mark.xfail(reason="Requirement for the future.")
    def test_analysis_with_non_exist_apk(self, sample_report, sample_rule_file):
        with pytest.raises(FileNotFoundError):
            sample_report.analysis("NON_EXIST_APK", sample_rule_file)

    @pytest.mark.xfail(reason="Requirement for the future.")
    def test_analysis_with_non_exist_rule(self, sample_report, sample_apk_file):
        with pytest.raises(FileNotFoundError):
            sample_report.analysis(sample_apk_file, "NON_EXIST_RULE")

    @pytest.mark.xfail(reason="Requirement for the future.")
    def test_analysis_with_both_invalid_files(self, sample_report, invalid_file):
        with pytest.raises(BaseException):
            sample_report.analysis(invalid_file, invalid_file)

    def test_analysis_with_dex_and_single_rule(
        self, sample_report, sample_dex_file, sample_rule_file
    ):

        with patch("quark.core.quark.Quark.run") as mock_run:
            with patch(
                "quark.core.quark.Quark.generate_json_report"
            ) as mock_generate_report:
                sample_report.analysis(sample_dex_file, sample_rule_file)

                mock_run.assert_called_once()
                mock_generate_report.assert_called_once()

    def test_analysis_with_apk_and_single_rule(
        self, sample_report, sample_apk_file, sample_rule_file
    ):

        with patch("quark.core.quark.Quark.run") as mock_run:
            with patch(
                "quark.core.quark.Quark.generate_json_report"
            ) as mock_generate_report:
                sample_report.analysis(sample_apk_file, sample_rule_file)

                mock_run.assert_called_once()
                mock_generate_report.assert_called_once()

    def test_analysis_with_rule_directory(
        self, sample_report, sample_apk_file, sample_rule_directory
    ):
        rule_list = [
            name
            for name in os.listdir(sample_rule_directory)
            if os.path.splitext(name)[1] == ".json"
        ]
        num_of_rules = len(rule_list)

        with patch("quark.core.quark.Quark.run") as mock_run:
            with patch(
                "quark.core.quark.Quark.generate_json_report"
            ) as mock_generate_report:

                sample_report.analysis(sample_apk_file, sample_rule_directory)

                assert mock_run.call_count == num_of_rules
                assert mock_generate_report.call_count == num_of_rules

    def test_get_report_with_invalid_type(self, sample_report):
        with pytest.raises(ValueError):
            sample_report.get_report(None)

    def test_get_report_with_invalid_value(self, sample_report):
        with pytest.raises(ValueError):
            sample_report.get_report("txt")

    def test_get_report_with_json_type(
        self, sample_report, sample_apk_file, sample_rule_file
    ):
        sample_report.analysis(sample_apk_file, sample_rule_file)

        result = sample_report.get_report("json")

        assert isinstance(result, dict)
        assert result["md5"] == "893e05aabd8754236ea70d3da8363d52"
        assert result["apk_filename"] == sample_apk_file
        assert result["size_bytes"] == 268043
        assert result["threat_level"] == "Low Risk"
        assert result["total_score"] == 4
        assert result["crimes"][0] is not None
