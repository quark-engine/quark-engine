import pytest

from quark.utils.weight import LEVEL_INFO, Weight


@pytest.fixture(params=[(20, 10), (30, 21), (50, 25)])
def expected_data(request):
    # (score_sum, weight_sum)
    return request.param


@pytest.fixture(params=[(0, 0), (100, 0), (20, 100), (-50, 20)])
def unexpected_data(request):
    # (score_sum, weight_sum)
    return request.param


class TestWeight:
    def test_init(self, expected_data):
        score_sum, weight_sum = expected_data

        weight_obj = Weight(score_sum, weight_sum)

        with pytest.raises(TypeError):
            _ = Weight()

        assert weight_obj.score_sum == score_sum
        assert weight_obj.weight_sum == weight_sum

    def test_level_info(self):
        assert LEVEL_INFO.LOW.value == "Low Risk"
        assert LEVEL_INFO.Moderate.value == "Moderate Risk"
        assert LEVEL_INFO.High.value == "High Risk"

    def test_calculate_with_expected_data(self, expected_data):
        score_sum, weight_sum = expected_data
        weight_obj = Weight(score_sum, weight_sum)

        assert weight_obj.calculate() in [
            "\x1b[92mLow Risk\x1b[0m",
            "\x1b[33mModerate Risk\x1b[0m",
            "\x1b[91mHigh Risk\x1b[0m",
        ]

    @pytest.mark.xfail(raises=ValueError)
    def test_calculate_with_unexpected_data(self, unexpected_data):
        score_sum, weight_sum = unexpected_data

        weight_obj = Weight(score_sum, weight_sum)

        assert weight_obj.calculate() in [
            "\x1b[92mLow Risk\x1b[0m",
            "\x1b[33mModerate Risk\x1b[0m",
            "\x1b[91mHigh Risk\x1b[0m",
        ]
