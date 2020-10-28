import json
import os

import click
from tqdm import tqdm

from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule
from quark.logo import logo
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.weight import Weight

logo()


@click.command()
@click.option("-s", "--summary", is_flag=True, help="Show summary report")
@click.option("-d", "--detail", is_flag=True, help="Show detail report")
@click.option(
    "-o",
    "--output",
    help="Output report as json file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
    required=False,
)
@click.option(
    "-a",
    "--apk",
    help="APK file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    required=True,
)
@click.option(
    "-r",
    "--rule",
    help="Rules folder need to be checked",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    required=True,
)
@click.option(
    "-g",
    "--graph",
    is_flag=True,
    help="Creating call graph and save it to call_graph_image directory",
    required=False,
)
@click.option(
    "-c",
    "--classification",
    is_flag=True,
    help="Show rules classification",
    required=False,
)
def entry_point(summary, detail, apk, rule, output, graph, classification):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""

    if summary:
        # show summary report
        # Load APK
        data = Quark(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            if single_rule.endswith("json"):
                rulepath = os.path.join(rule, single_rule)
                rule_checker = QuarkRule(rulepath)

                # Run the checker
                data.run(rule_checker)

                data.show_summary_report(rule_checker)

        w = Weight(data.quark_analysis.score_sum, data.quark_analysis.weight_sum)
        print_warning(w.calculate())
        print_info("Total Score: " + str(data.quark_analysis.score_sum))
        print(data.quark_analysis.summary_report_table)

        if classification:
            data.show_rule_classification()
        if graph:
            data.show_call_graph()

    if detail:
        # show summary report

        # Load APK
        data = Quark(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            if single_rule.endswith("json"):
                rulepath = os.path.join(rule, single_rule)
                print(rulepath)
                rule_checker = QuarkRule(rulepath)

                # Run the checker
                data.run(rule_checker)

                data.show_detail_report(rule_checker)
                print_success("OK")

        if classification:
            data.show_rule_classification()
        if graph:
            data.show_call_graph()

    if output:
        # show json report

        # Load APK
        data = Quark(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            if single_rule.endswith("json"):
                rulepath = os.path.join(rule, single_rule)
                rule_checker = QuarkRule(rulepath)

                # Run the checker
                data.run(rule_checker)

                data.generate_json_report(rule_checker)

        json_report = data.get_json_report()

        with open(output, "w") as f:
            json.dump(json_report, f, indent=4)
            f.close()


if __name__ == "__main__":
    entry_point()
