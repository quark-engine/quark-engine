import json
import os


class RuleObject:
    def __init__(self, json_filename):
        self.check_item = [False, False, False, False, False]

        with open(json_filename, "r") as f:
            self._json_obj = json.loads(f.read())
            self._crime = self._json_obj["crime"]
            self._x1_permission = self._json_obj["x1_permission"]
            self._x2n3n4_comb = self._json_obj["x2n3n4_comb"]
            self._yscore = self._json_obj["yscore"]
            self.rule_filename = os.path.basename(json_filename)

    def __repr__(self):
        return "<RuleObject-{}>".format(self.rule_filename)

    @property
    def crime(self):
        return self._crime

    @property
    def x1_permission(self):
        return self._x1_permission

    @property
    def x2n3n4_comb(self):
        return self._x2n3n4_comb

    @property
    def yscore(self):
        return self._yscore

    def get_score(self, confidence):
        """
        the number of confidence will turn
        into the threshold.

        2^(confidence - 1)
        """
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * self._yscore) / 2 ** 4


if __name__ == "__main__":
    pass
