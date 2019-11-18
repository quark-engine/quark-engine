import pytest

from quark.utils.weight import Weight, LEVEL_INFO


@pytest.fixture(params=[(20, 10), (30, 21), (50, 25)])
def data(request):
    # (score_sum, weight_sum)
    return request.param


@pytest.fixture(params=[(0, 0), (100, 0), (20, 100), (-50, 20)])
def expected_failed_data(request):
    # (score_sum, weight_sum)
    return request.param


class TestWeight(object):
    def test_init(self, data):
        score_sum, weight_sum = data

        weight_obj = Weight(score_sum, weight_sum)

        with pytest.raises(TypeError):
            weight_obj_no_argu = Weight()

        assert weight_obj.score_sum == score_sum
        assert weight_obj.weight_sum == weight_sum
        assert isinstance(weight_obj, Weight)

    def test_level_info(self):
        assert LEVEL_INFO.LOW.value == "Low Risk"
        assert LEVEL_INFO.Moderate.value == "Moderate Risk"
        assert LEVEL_INFO.High.value == "High Risk"

    def test_calculate(self, data):
        score_sum, weight_sum = data
        weight_obj = Weight(score_sum, weight_sum)

        assert weight_obj.calculate() in [
            "\x1b[32mLow Risk\x1b[0m",
            "\x1b[33mModerate Risk\x1b[0m",
            "\x1b[31mHigh Risk\x1b[0m",
        ]

    @pytest.mark.xfail(raises=ValueError)
    def test_calculate_with_value_error(self, expected_failed_data):
        score_sum, weight_sum = expected_failed_data

        weight_obj = Weight(score_sum, weight_sum)

        assert weight_obj.calculate() in [
            "\x1b[32mLow Risk\x1b[0m",
            "\x1b[33mModerate Risk\x1b[0m",
            "\x1b[31mHigh Risk\x1b[0m",
        ]
