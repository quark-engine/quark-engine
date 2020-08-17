import click
import json
import os
from quark.Objects.ruleobject import RuleObject
from quark.Objects.xrule import XRule
from quark.logo import logo
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.weight import Weight
from tqdm import tqdm

logo()


@click.command()
@click.option("--summary", "-s", is_flag=True, help='show summary report')
@click.option("--detail", "-d", is_flag=True, help="show detail report")
@click.option(
    "-o", "--output", help="Output report as json file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
    required=False,
)
@click.option(
    "-a", "--apk", help="APK file", type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
)
@click.option(
    "-r", "--rule", help="Rules folder need to be checked",
    type=click.Path(exists=True, file_okay=False, dir_okay=True), required=True,
)
def entry_point(summary, detail, apk, rule, output):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""

    if summary:
        # show summary report
        # Load APK
        data = XRule(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_summary_report(rule_checker)

        w = Weight(data.score_sum, data.weight_sum)
        print_warning(w.calculate())
        print_info("Total Score: " + str(data.score_sum))
        print(data.tb)

    if detail:
        # show summary report

        # Load APK
        data = XRule(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            print(rulepath)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_detail_report(rule_checker)
            print_success("OK")

    if output:
        # show json report

        # Load APK
        data = XRule(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_json_report(rule_checker)

        json_report = data.get_json_report()

        with open(output, "w") as f:
            json.dump(json_report, f, indent=4)
            f.close()

        print(f"Output report to > {output}")


if __name__ == '__main__':
    entry_point()
