from quark.webreport.generate import ReportGenerator
import importlib_resources


class TestReportGenerator:

    def testLoadingHtmlLayout(self) -> None:
        reportGenerator = ReportGenerator(None)

        ruleGenLayoutPath = (
            importlib_resources.files("quark.webreport")
            / "genrule_report_layout.html"
        )
        with importlib_resources.as_file(ruleGenLayoutPath) as file:
            a = file.read_text()
            assert reportGenerator.rulegenerate_layout == file.read_text()

        analysisResultLayoutPath = (
            importlib_resources.files("quark.webreport")
            / "analysis_report_layout.html"
        )
        with importlib_resources.as_file(analysisResultLayoutPath) as file:
            assert reportGenerator.analysis_result_layout == file.read_text()
