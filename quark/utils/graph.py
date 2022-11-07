# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import sys
import os

import plotly.graph_objects as go
from graphviz import Digraph
from prompt_toolkit.shortcuts import checkboxlist_dialog


def wrapper_lookup(apkinfo, method, native_api):
    visited_method_list = set()
    stack = [method]

    while stack:
        parent = stack[-1]
        if parent not in visited_method_list:
            visited_method_list.add(parent)

            submethods = {reference[0] for reference in apkinfo.lowerfunc(parent)}
            if native_api in submethods:
                return [parent]

            next_level = filter(lambda m: not m.is_android_api(), submethods)
            stack.extend(next_level)
        else:
            stack.pop()

    return []


def call_graph(call_graph_analysis, output_format="png"):
    """
    Generating a call graph based on two native Android APIs.
    """

    parent_function = call_graph_analysis["parent"]
    apkinfo = call_graph_analysis["apkinfo"]
    first_call = call_graph_analysis["first_call"]
    second_call = call_graph_analysis["second_call"]
    first_api = call_graph_analysis["first_api"]
    second_api = call_graph_analysis["second_api"]
    crime = call_graph_analysis["crime"]

    if first_call != first_api:
        first_wrapper = wrapper_lookup(apkinfo, first_call, first_api)
    if second_call != second_api:
        second_wrapper = wrapper_lookup(apkinfo, second_call, second_api)

    # Initialize the Digraph object
    dot = Digraph(
        filename=f"{parent_function.name}_{first_call.name}_{second_call.name}",
        node_attr={"fontname": "Courier New Bold"},
        comment="Quark-Engine Call Graph Result",
        format=output_format,
        graph_attr={
            "label": f"Potential Malicious Activity: {crime}",
            "labelloc": "top",
            "center": "true",
        },
    )
    dot.attr(compound="true")

    with dot.subgraph(name="cluster_mutual") as mutual_parent_function_description:
        mutual_parent_function_description.attr(
            style="rounded",
            penwidth="1",
            fillcolor="white",
            fontname="Courier New",
            shape="box",
        )
        mutual_parent_function_description.attr(
            label="Mutual Parent Function", fontname="Courier New Bold"
        )

        # mutual parent function node
        p, r = str(parent_function.descriptor).split(")")
        mutual_parent_function_description.node(
            f"{parent_function.full_name}",
            label=f"Access: {parent_function.access_flags}\nClass: {parent_function.class_name}\nMethod: {parent_function.name}\n Parameter: {p})\n Return: {r}",
            shape="none",
            fontcolor="blue",
            fontname="Courier New",
        )

    with dot.subgraph(name="cluster_0") as wrapper:
        wrapper.attr(label="Wrapped Functions", fontname="Courier New Bold")
        wrapper.attr(style="rounded", penwidth="1", fillcolor="red", shape="box")
        # Build the first call nodes

        if first_call != first_api:

            for wp_func in first_wrapper:
                p, r = str(wp_func.descriptor).split(")")

                wrapper.node(
                    f"{wp_func.full_name}",
                    label=f"Access: {wp_func.access_flags}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
                    style="rounded",
                    fontcolor="blue",
                    penwidth="1",
                    fillcolor="white",
                    fontname="Courier New",
                    shape="none",
                )

            # wrapper -> wrapper
            for i in range(len(first_wrapper) - 1, 0, -1):
                wrapper.edge(
                    f"{first_wrapper[i].full_name}",
                    f"{first_wrapper[i - 1].full_name}",
                    "calls",
                    fontname="Courier New",
                )

        if second_call != second_api:

            for wp_func in second_wrapper:
                p, r = str(wp_func.descriptor).split(")")
                wrapper.node(
                    f"{wp_func.full_name}",
                    label=f"Access: {wp_func.access_flags}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
                    style="rounded",
                    fontcolor="blue",
                    penwidth="1",
                    fillcolor="white",
                    fontname="Courier New",
                    shape="none",
                )

            # wrapper -> wrapper
            for i in range(len(second_wrapper) - 1, 0, -1):
                wrapper.edge(
                    f"{second_wrapper[i].full_name}",
                    f"{second_wrapper[i - 1].full_name}",
                    "calls",
                    fontname="Courier New",
                )

    with dot.subgraph(name="cluster_1") as native_call_subgraph:
        native_call_subgraph.attr(
            style="rounded",
            penwidth="1",
            fillcolor="white",
            fontname="Courier New",
            shape="box",
        )
        native_call_subgraph.attr(label="Native API Calls", fontname="Courier New Bold")
        # Native API Calls

        native_call_subgraph.node(
            f"{first_api.full_name}",
            label=f"Class: {first_api.class_name}\nMethod: {first_api.name}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )
        native_call_subgraph.node(
            f"{second_api.full_name}",
            label=f"Class: {second_api.class_name}\nMethod: {second_api.name}",
            fontcolor="blue",
            shape="none",
            fontname="Courier New",
        )

    # mutual parent function -> the first node of each node

    if first_call != first_api:

        dot.edge(
            f"{parent_function.full_name}",
            f"{first_wrapper[-1].full_name}",
            "First Call",
            fontname="Courier New",
        )

        dot.edge(
            f"{first_wrapper[0].full_name}",
            f"{first_api.full_name}",
            "calls",
            fontname="Courier New",
        )
    else:
        dot.edge(
            f"{parent_function.full_name}",
            f"{first_api.full_name}",
            "First Call",
            fontname="Courier New",
        )

    if second_call != second_api:
        dot.edge(
            f"{parent_function.full_name}",
            f"{second_wrapper[-1].full_name}",
            "Second Call",
            fontname="Courier New",
        )

        dot.edge(
            f"{second_wrapper[0].full_name}",
            f"{second_api.full_name}",
            "calls",
            fontname="Courier New",
        )
    else:
        dot.edge(
            f"{parent_function.full_name}",
            f"{second_api.full_name}",
            "Second Call",
            fontname="Courier New",
        )

    dot.render(
        f"call_graph_image/{parent_function.name}_{first_call.name}_{second_call.name}"
    )


def show_comparison_graph(title, labels, malware_confidences, font_size=22):
    """
    show radar chart based on max label confidence of several malwares
    :param title: title of the graph to be displayed
    :param labels: labels to be shown on the radar chart
    :param malware_confidences: dictionary with structure, malware_name=[
    array of confidences to be shown on radar chart]
    :return: None
    """
    fig = go.Figure()
    # plot the graph with specific layout
    fig.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100], dtick=20)),
        showlegend=True,
        title={
            "text": f"<b>{title}</b>",
        },
        font=dict(size=font_size),
        title_x=0.5,
        legend=dict(
            y=0.5,
            x=0.8,
            traceorder="normal",
        ),
    )
    for malware_name in malware_confidences:
        fig.add_trace(
            go.Scatterpolar(
                r=malware_confidences[malware_name],
                theta=labels,
                fill="toself",
                name=malware_name,
                line=dict(
                    width=4,
                ),
            )
        )
    fig.show()
    if not os.path.exists("behaviors_comparison_radar_chart"):
        os.mkdir("behaviors_comparison_radar_chart")
    fig.write_image("behaviors_comparison_radar_chart/compariso_image.jpeg")


def select_label_menu(all_labels, min_labels=5, max_labels=10):
    """
    allows user to select label to be shown in radar chart
    :param all_labels: all label found on the rules
    :param min_labels: min label to be shown on radar chart (default 5)
    :param max_labels: max label to be shown on radar chart (default 10)
    :return: label selected
    """

    value_pair = [(label, label) for label in all_labels]

    while True:
        results_array = checkboxlist_dialog(
            title="Label-base Report",
            text=f"Select number of labels between {min_labels} and {max_labels}",
            values=value_pair,
        ).run()

        if results_array:

            if min_labels <= len(results_array) <= max_labels:
                break
        else:
            # user selects "Cancel" to leave the program.
            print("Canceled!")
            sys.exit()

    return results_array
