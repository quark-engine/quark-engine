import pytest

from quark.utils.weight import LEVEL_INFO, Weight


@pytest.fixture(
    params=[
        (20, 10),
        (30, 21),
        (50, 25),
        (100, -10),
        (-100, -10),
        (-100, 10),
        (0, 1),
        (0, 0),
    ]
)
def total_rule_score_and_apk_score(request):
    return request.param


class TestWeight:
    def test_init(self, total_rule_score_and_apk_score):
        score_sum, weight_sum = total_rule_score_and_apk_score

        weight_obj = Weight(score_sum, weight_sum)

        with pytest.raises(TypeError):
            _ = Weight()

        assert weight_obj.score_sum == score_sum
        assert weight_obj.weight_sum == weight_sum

    def test_level_info(self):
        assert LEVEL_INFO.LOW.value == "Low Risk"
        assert LEVEL_INFO.Moderate.value == "Moderate Risk"
        assert LEVEL_INFO.High.value == "High Risk"

    def test_calculate(self, total_rule_score_and_apk_score):
        score_sum, weight_sum = total_rule_score_and_apk_score
        weight_obj = Weight(score_sum, weight_sum)

        assert weight_obj.calculate() in [
            "\x1b[92mLow Risk\x1b[0m",
            "\x1b[33mModerate Risk\x1b[0m",
            "\x1b[91mHigh Risk\x1b[0m",
        ]
