from enum import Enum

class LEVEL_INFO(Enum):
    LOW = "Low Risk"
    Moderate = "Moderate Rist"
    High = "High Risk"


class Weight:

    def __init__(self, score_sum, weight_sum):
        self.score_sum = score_sum
        self.weight_sum = weight_sum

    def calculate(self):

        # Level 1 threshold
        level_one_threshold = self.score_sum / 2**4
        # Level 2 threshold
        level_two_threshold = self.score_sum / 2**3
        # Level 3 threshold
        level_three_threshold = self.score_sum / 2**2
        # Level 4 threshold
        level_four_threshold = self.score_sum / 2**1
        # Level 5 threshold
        level_five_threshold = self.score_sum / 2**0


        total_weight = self.weight_sum
        print(total_weight)

        if total_weight > 0 and total_weight <= level_one_threshold:
            return LEVEL_INFO.LOW.value

        elif total_weight > level_one_threshold and total_weight <= level_two_threshold:
            return LEVEL_INFO.LOW.value

        elif total_weight > level_two_threshold and total_weight <= level_three_threshold:
            return LEVEL_INFO.Moderate.value

        elif total_weight > level_three_threshold and total_weight <= level_four_threshold:
            return LEVEL_INFO.Moderate.value

        elif total_weight > level_four_threshold and total_weight <= level_five_threshold:
            return LEVEL_INFO.High.value

        else:
            raise ValueError("Weight calculate failed")
        
if __name__ == '__main__':
    pass

