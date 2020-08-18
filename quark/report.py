import os

from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule


class Report:

    def __init__(self):
        self.quark = None

    def analysis(self, apk, rule):

        self.quark = Quark(apk)

        if os.path.isdir(rule):

            rules_list = os.listdir(rule)

            for single_rule in rules_list:
                rulepath = os.path.join(rule, single_rule)
                rule_checker = QuarkRule(rulepath)

                # Run the checker
                self.quark.run(rule_checker)

                # Generate json report
                self.quark.generate_json_report(rule_checker)

        elif os.path.isfile(rule):
            rule = QuarkRule(rule)
            # Run checker
            self.quark.run(rule)
            # Generate json report
            self.quark.generate_json_report(rule)

    def get_report(self, report_type):

        if report_type == "json":
            return self.quark.get_json_report()
