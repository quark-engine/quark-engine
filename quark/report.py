# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from quark.utils.tools import find_rizin


class Report:
    """
    This module is for users who want to use quark as a Python module.
    """

    def __init__(self, rizin_path=None, disable_rizin_installation=False):
        """
        Create a Report object.

        :param rizin_path: a PathLike object to specify a Rizin executable for
        the Rizin-based analysis library. Defaults to None
        :param disable_rizin_installation: a flag to disable the automatic
        installation of Rizin. Defaults to False. Defaults to False
        """
        self.quark = None
        self.rizin_path = rizin_path
        self.disable_rizin_installation = disable_rizin_installation

    def analysis(self, apk, rule, core_library="androguard", rizin_path=None):
        """
        The main function of Quark-Engine analysis, the analysis is based on
        the provided APK file.

        :param apk: an APK for Quark to analyze
        :param rule: a Quark rule that will be used in the analysis. It could
        be a directory or a Quark rule
        :param core_library: a string indicating which analysis library Quark
        should use. Defaults to "androguard"
        :param rizin_path: a PathLike object to specify a Rizin executable for
        the Rizin-based analysis library. Defaults to None
        :return: None
        """

        if core_library.lower() == "rizin":
            if rizin_path:
                self.rizin_path = rizin_path
            elif not self.rizin_path:
                self.rizin_path = find_rizin(
                    disable_rizin_installation=self.disable_rizin_installation
                )

                if not self.rizin_path:
                    raise ValueError("Cannot found a valid Rizin executable.")

        self.quark = Quark(apk, core_library, self.rizin_path)

        if os.path.isdir(rule):

            rules_list = os.listdir(rule)

            for single_rule in rules_list:
                if single_rule.endswith("json"):
                    rule_path = os.path.join(rule, single_rule)
                    rule_checker = RuleObject(rule_path)

                    # Run the checker
                    self.quark.run(rule_checker)

                    # Generate json report
                    self.quark.generate_json_report(rule_checker)

        elif os.path.isfile(rule):
            if rule.endswith("json"):
                rule = RuleObject(rule)
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

        raise ValueError(
            "The format are not supported, please refer to the Quark manual."
        )
