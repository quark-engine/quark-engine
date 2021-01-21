# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from graphviz import Digraph


def wrapper_lookup(wrapper, top_method, native_api):
    next_level = []

    for _, method, _ in top_method.get_xref_to():
        if method == native_api:
            wrapper.append(top_method)
            return
        elif method.is_android_api():
            continue
        else:
            next_level.append(method)

    for next_level_method in next_level:
        wrapper_lookup(wrapper, next_level_method, native_api)


def call_graph(call_graph_analysis):
    """
    Generating a call graph based on two native Android APIs.
    """

    parent_function = call_graph_analysis["parent"]
    first_call = call_graph_analysis["first_call"]
    second_call = call_graph_analysis["second_call"]
    first_api = call_graph_analysis["first_api"]
    second_api = call_graph_analysis["second_api"]
    crime = call_graph_analysis["crime"]

    first_wrapper = []
    second_wrapper = []

    if first_call != first_api:
        wrapper_lookup(first_wrapper, first_call, first_api)
    if second_call != second_api:
        wrapper_lookup(second_wrapper, second_call, second_api)

    # Initialize the Digraph object
    dot = Digraph(
        filename=f"{parent_function.name}_{first_call.name}_{second_call.name}",
        node_attr={"fontname": "Courier New Bold"},
        comment="Quark-Engine Call Graph Result",
        format="png",
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
            label=f"Access: {parent_function.access}\nClass: {parent_function.class_name}\nMethod: {parent_function.name}\n Parameter: {p})\n Return: {r}",
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
                    label=f"Access: {wp_func.access}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
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
                    label=f"Access: {wp_func.access}\nClass: {wp_func.class_name}\nMethod: {wp_func.name}\n Parameter: {p})\n Return: {r}",
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

    dot.render(f"call_graph_image/{parent_function.name}_{first_call.name}_{second_call.name}")
