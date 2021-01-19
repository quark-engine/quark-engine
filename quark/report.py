# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os

from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule


class Report:
    """
    This module is for users who want to use quark as a Python module.
    """

    def __init__(self):
        self.quark = None

    def analysis(self, apk, rule):
        """
        The main function of Quark-Engine analysis, the analysis is based on the provided APK file.

        :param apk: the APK file
        :param rule: the rule to be checked, it could be a directory or a single json rule
        :return: None
        """

        self.quark = Quark(apk)

        if os.path.isdir(rule):

            rules_list = os.listdir(rule)

            for single_rule in rules_list:
                if single_rule.endswith("json"):
                    rulepath = os.path.join(rule, single_rule)
                    rule_checker = QuarkRule(rulepath)

                    # Run the checker
                    self.quark.run(rule_checker)

                    # Generate json report
                    self.quark.generate_json_report(rule_checker)

        elif os.path.isfile(rule):
            if rule.endswith("json"):
                rule = QuarkRule(rule)
                # Run checker
                self.quark.run(rule)
                # Generate json report
                self.quark.generate_json_report(rule)

    def get_report(self, report_type):
        """
        Output the Quark-Engine report according to the report_type argument.

        :param report_type: string of the report format
        :return: string of the quark report with the format you specify
        """

        if report_type == "json":
            return self.quark.get_json_report()

        raise ValueError("The format are not supported, please refer to the Quark manual.")
