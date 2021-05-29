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
from quark.logo import logo
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.weight import Weight
from quark.utils.colors import yellow

from simple_term_menu import TerminalMenu
import plotly.graph_objects as go
import numpy as np

logo()


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
    multiple=True,
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
    help="List classes, methods and descriptors",
    type=click.Choice(["all", "native", "custom"]),
    required=False,
)
@click.option(
    "-p",
    "--permission",
    help="List Android permissions",
    is_flag=True,
    required=False,
)
@click.option(
    "-l",
    "--label",
    help="Show report based on label of rules",
    type=click.Choice(["max", "detailed"]),
    required=False,
)
@click.option(
    "-C",
    "--comparison",
    help="Malware comparison based on rule labels max confidence",
    required=False,
    is_flag=True,
)
def entry_point(
    summary,
    detail,
    apk,
    rule,
    output,
    graph,
    classification,
    threshold,
    list,
    permission,
    label,
    comparison,
):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""

    # Load APK
    data = Quark(apk[0])

    # Load rules
    rules_list = [x for x in os.listdir(rule) if x.endswith("json")]
    
    if comparison:

        # selection of labels on which it will be done the comparison on radar chart
        # first look for all label found in the rule list
        all_labels = []
        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = QuarkRule(rulepath)
            labels = (
                rule_checker._label
            )  # array type, e.g. ['network', 'collection']
            for single_label in labels:
                if single_label not in all_labels:
                    all_labels.append(single_label)

        # let user choose a list of label on which it will be performed the analysis
        terminal_menu = TerminalMenu(
            all_labels,
            multi_select=True,
            show_multi_select_hint=False,
        )
        max_labels = 10
        min_labels = 5
        while True:
            menu_entry_indices = terminal_menu.show()
            if len(menu_entry_indices) in range(min_labels, max_labels + 1):
                break
            print(
                "Select numbers of labels in range ["
                + str(min_labels)
                + ","
                + str(max_labels)
                + "]\n"
            )
        selected_label = np.array(terminal_menu.chosen_menu_entries)

        # initialize Figure object used to build the graph
        fig = go.Figure()

        # perform label based analysis on the apk_
        for apk_ in apk:
            data = Quark(apk_)
            all_labels = {}
            # dictionary containing
            # key: label
            # value: list of confidence values
            # $ print(all_rules["accessibility service"])
            # > [60, 40, 60, 40, 60, 40]

            for single_rule in tqdm(rules_list):
                rulepath = os.path.join(rule, single_rule)
                rule_checker = QuarkRule(rulepath)

                # analyse malware only on rules where appears label selected
                labels = np.array(rule_checker._label)
                if len(np.intersect1d(labels, selected_label)) == 0:
                    continue

                # Run the checker
                data.run(rule_checker)
                confidence = rule_checker.check_item.count(True) * 20
                labels = (
                    rule_checker._label
                )  # array type, e.g. ['network', 'collection']
                for single_label in labels:
                    if single_label in all_labels:
                        all_labels[single_label].append(confidence)
                    else:
                        all_labels[single_label] = [confidence]

            # extrapolate data used to plot radar chart
            radar_data = {}
            for _label in selected_label:
                confidences = np.array(all_labels[_label])
                # on radar data use the maximum confidence for a certain label
                radar_data[_label] = np.max(confidences)

            radar_confidence = []
            for _label in radar_data:
                radar_confidence.append(radar_data[_label])

            fig.add_trace(
                go.Scatterpolar(
                    r=radar_confidence,
                    theta=selected_label,
                    fill="toself",
                    name=apk_.split("/")[-1],
                    line=dict(
                        width=4,
                    ),
                )
            )
        # plot the graph with specific layout
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
            showlegend=True,
        )
        fig.show()

    if label:
        all_labels = {}
        # dictionary containing
        # key: label
        # value: list of confidence values
        # $ print(all_rules["accessibility service"])
        # > [60, 40, 60, 40, 60, 40]

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            rule_checker = QuarkRule(rulepath)
            # Run the checker
            data.run(rule_checker)
            confidence = rule_checker.check_item.count(True) * 20
            labels = rule_checker._label  # array type, e.g. ['network', 'collection']
            for single_label in labels:
                if single_label in all_labels:
                    all_labels[single_label].append(confidence)
                else:
                    all_labels[single_label] = [confidence]

        # get how many label with max confidence >= 80%
        counter_high_confidence = 0
        for single_label in all_labels:
            if max(all_labels[single_label]) >= 80:
                counter_high_confidence += 1

        print_info("Total Label found: " + yellow(str(len(all_labels))))
        print_info(
            "Rules with label which max confidence >= 80%: "
            + yellow(str(counter_high_confidence))
        )

        data.show_label_report(rule, all_labels, label)
        print(data.quark_analysis.label_report_table)

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

        if list == "all":
            for all_method in data.apkinfo.all_methods:
                print(all_method.full_name)
        if list == "native":
            for api in data.apkinfo.android_apis:
                print(api.full_name)
        if list == "custom":
            for custom_method in data.apkinfo.custom_methods:
                print(custom_method.full_name)

    if permission:

        for p in data.apkinfo.permissions:
            print(p)


if __name__ == "__main__":
    entry_point()
