# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
import os
from quark.utils.tools import descriptor_to_androguard_format


class RuleObject:
    """RuleObject is used to store the rule from json file"""

    __slots__ = [
        "check_item",
        "_json_obj",
        "_crime",
        "_permission",
        "_api",
        "_score",
        "rule_filename",
        "_label",
    ]

    def __init__(self, json_filename, json_data=None):
        """
        According to customized JSON rules, calculate the weighted score and assessing the stages of the crime.

        :param json_filename:
        """
        # the state of five stages
        self.check_item = [False, False, False, False, False]

        if json_data is not None:
            self._json_obj = json_data
        else:
            with open(json_filename) as json_file:
                self._json_obj = json.loads(json_file.read())

        self._crime = self._json_obj["crime"]
        self._permission = self._json_obj["permission"]

        self._api = self._json_obj["api"]
        for index in range(len(self._api)):
            descriptor = self._api[index]["descriptor"]
            if " " not in descriptor:
                self._api[index][
                    "descriptor"
                ] = descriptor_to_androguard_format(descriptor)

        self._score = self._json_obj["score"]
        self.rule_filename = os.path.basename(json_filename)
        self._label = self._json_obj["label"]

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
    def permission(self):
        """
        Permission requested by the apk to practice the crime.

        :return: a list of given permissions
        """
        return self._permission

    @property
    def api(self):
        """
        Key native APIs that do the action and target in order.

        :return: a list recording the APIs class_name and method_name in order
        """
        return self._api

    @property
    def label(self):
        """
        A list contains various lebels described in https://github.com/quark-engine/quark-rules/blob/master/label_desc.csv

        :return: a label list defined in rules
        """
        return self._label

    @property
    def score(self):
        """
        The value used to calculate the weighted score

        :return: integer
        """
        return self._score

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
        return (2 ** (confidence - 1) * self._score) / 2 ** 4


if __name__ == "__main__":
    pass
