from collections import defaultdict

from quark.Objects.analysis import QuarkAnalysis


class TestQuarkAnalysis:
    def test_init(self):
        analysis = QuarkAnalysis()
        summary_table_field_list = [
            "Filename",
            "Rule",
            "Confidence",
            "Score",
            "Weight",
        ]
        label_table_field_list = [
            "Label",
            "Description",
            "Number of rules",
            "MAX Confidence %",
        ]

        assert analysis.crime_description == ""
        assert analysis.first_api is None
        assert analysis.second_api is None
        assert analysis.level_1_result == []
        assert analysis.level_2_result == []
        assert analysis.level_3_result == []
        assert analysis.level_4_result == []
        assert analysis.level_5_result == []

        assert analysis.json_report == []
        assert analysis.weight_sum == 0
        assert analysis.score_sum == 0
        assert all(
            [
                label
                for label in summary_table_field_list
                if label in analysis.summary_report_table
            ]
        )
        assert all(
            [
                label
                for label in label_table_field_list
                if label in analysis.label_report_table
            ]
        )

        assert analysis.call_graph_analysis_list == []
        assert isinstance(analysis.parent_wrapper_mapping, defaultdict)
        assert len(analysis.parent_wrapper_mapping.items()) == 0

    def test_clean_result(self):
        analysis = QuarkAnalysis()
        analysis.level_1_result = ["123"]
        analysis.level_2_result = ["123"]
        analysis.level_3_result = ["123"]
        analysis.level_4_result = ["123"]
        analysis.level_5_result = ["123"]

        analysis.clean_result()

        assert analysis.level_1_result == []
        assert analysis.level_2_result == []
        assert analysis.level_3_result == []
        assert analysis.level_4_result == []
        assert analysis.level_5_result == []
