# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import json
import os

import click
from tqdm import tqdm

from quark import config
from quark.Objects.quark import Quark
from quark.Objects.quarkrule import QuarkRule
from quark.freshquark import check_update
from quark.logo import logo
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.weight import Weight

logo()
check_update()


@click.command(no_args_is_help=True)
@click.option("-s", "--summary", is_flag=True, help="Show summary report")
@click.option("-d", "--detail", is_flag=True, help="Show detail report")
@click.option(
    "-o",
    "--output",
    help="Output report in JSON",
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
    help="Rules directory",
    type=click.Path(exists=True, file_okay=True, dir_okay=True),
    default=f"{config.HOME_DIR}quark-rules",
    required=False,
    show_default=True,
)
@click.option(
    "-g",
    "--graph",
    is_flag=True,
    help="Create call graph to call_graph_image directory",
    required=False,
)
@click.option(
    "-c",
    "--classification",
    is_flag=True,
    help="Show rules classification",
    required=False,
)
@click.option(
    "-t",
    "--threshold",
    help="Set the confidence threshold",
    type=click.Choice(["100", "80", "60", "40", "20"]),
    required=False,
)
@click.option(
    "-i",
    "--list",
    is_flag=True,
    help="List classes, methods and descriptors",
    required=False,
)
def entry_point(
    summary, detail, apk, rule, output, graph, classification, threshold, list
):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""

    # Load APK
    data = Quark(apk)

    # Load rules
    rules_list = [x for x in os.listdir(rule) if x.endswith("json")]

    # Show summary report
    if summary:

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = QuarkRule(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_summary_report(rule_checker, threshold)

        w = Weight(data.quark_analysis.score_sum, data.quark_analysis.weight_sum)
        print_warning(w.calculate())
        print_info("Total Score: " + str(data.quark_analysis.score_sum))
        print(data.quark_analysis.summary_report_table)

        if classification:
            data.show_rule_classification()
        if graph:
            data.show_call_graph()

    # Show detail report
    if detail:

        for single_rule in tqdm(rules_list):
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

    # Show JSON report
    if output:

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = QuarkRule(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.generate_json_report(rule_checker)

        json_report = data.get_json_report()

        with open(output, "w") as file:
            json.dump(json_report, file, indent=4)
            file.close()

    if list:

        for api in data.apkinfo.android_apis:
            print(api.full_name)


if __name__ == "__main__":
    entry_point()
