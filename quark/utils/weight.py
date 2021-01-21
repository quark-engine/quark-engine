# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from enum import Enum

from quark.utils.colors import green, yellow, yel, red


class LEVEL_INFO(Enum):
    LOW = "Low Risk"
    Moderate = "Moderate Risk"
    High = "High Risk"


class Weight:
    def __init__(self, score_sum, weight_sum):
        self.score_sum = score_sum
        self.weight_sum = weight_sum

    def calculate(self):

        # Level 1 threshold
        level_one_threshold = self.score_sum / 2 ** 4
        # Level 2 threshold
        level_two_threshold = self.score_sum / 2 ** 3
        # Level 3 threshold
        level_three_threshold = self.score_sum / 2 ** 2
        # Level 4 threshold
        level_four_threshold = self.score_sum / 2 ** 1
        # Level 5 threshold
        level_five_threshold = self.score_sum / 2 ** 0

        total_weight = self.weight_sum

        if 0 <= total_weight <= level_one_threshold:
            return green(LEVEL_INFO.LOW.value)

        elif level_one_threshold < total_weight <= level_two_threshold:
            return green(LEVEL_INFO.LOW.value)

        elif level_two_threshold < total_weight <= level_three_threshold:
            return yellow(LEVEL_INFO.Moderate.value)

        elif level_three_threshold < total_weight <= level_four_threshold:
            return yel(LEVEL_INFO.Moderate.value)

        elif level_four_threshold < total_weight <= level_five_threshold:
            return red(LEVEL_INFO.High.value)

        else:
            raise ValueError("Weight calculate failed")


if __name__ == "__main__":
    w = Weight(29, 19)
    print(w.calculate())
