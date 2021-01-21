# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
import os


class QuarkRule:
    """RuleObject is used to store the rule from json file"""

    __slots__ = ["check_item", "_json_obj", "_crime", "_x1_permission", "_x2n3n4_comb", "_yscore", "rule_filename"]

    def __init__(self, json_filename):
        """
        According to customized JSON rules, calculate the weighted score and assessing the stages of the crime.

        :param json_filename:
        """
        # the state of five stages
        self.check_item = [False, False, False, False, False]

        with open(json_filename) as json_file:
            self._json_obj = json.loads(json_file.read())
            self._crime = self._json_obj["crime"]
            self._x1_permission = self._json_obj["x1_permission"]
            self._x2n3n4_comb = self._json_obj["x2n3n4_comb"]
            self._yscore = self._json_obj["yscore"]
            self.rule_filename = os.path.basename(json_filename)

    def __repr__(self):
        return f"<RuleObject-{self.rule_filename}>"

    @property
    def crime(self):
        """
        Description of given crime.

        :return: a string of the crime
        """
        return self._crime

    @property
    def x1_permission(self):
        """
        Permission requested by the apk to practice the crime.

        :return: a list of given permissions
        """
        return self._x1_permission

    @property
    def x2n3n4_comb(self):
        """
        Key native APIs that do the action and target in order.

        :return: a list recording the APIs class_name and method_name in order
        """
        return self._x2n3n4_comb

    @property
    def yscore(self):
        """
        The value used to calculate the weighted score

        :return: integer
        """
        return self._yscore

    def get_score(self, confidence):
        """
        According to the state of the five stages, we calculate the weighted score based on exponential growth.
        For example, we captured the third stage in five stages, then the weighted score would be (2^3-1) / 2^4.

        2^(confidence - 1)

        :param confidence:
        :return: floating point
        """
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * self._yscore) / 2 ** 4


if __name__ == "__main__":
    pass
