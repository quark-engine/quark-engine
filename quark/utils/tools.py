# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import copy
import re
from typing import Any, List, Union


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def contains(subset_to_check, target_list):
    """
    Check the sequence pattern within two list.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["put", "getCellLocation", "query", "sendTextMessage"]
    then it will return true.
    -----------------------------------------------------------------
    subset_to_check = ["getCellLocation", "sendTextMessage"]
    target_list = ["sendTextMessage", "put", "getCellLocation", "query"]
    then it will return False.
    """

    target_copy = copy.copy(target_list)

    # Delete elements that do not exist in the subset_to_check list
    for item in target_copy:
        if item not in subset_to_check:
            target_copy.remove(item)

    for i in range(len(target_copy) - len(subset_to_check) + 1):
        for j in range(len(subset_to_check)):
            if target_copy[i + j] != subset_to_check[j]:
                break
        else:
            return True
    return False


def descriptor_to_androguard_format(descriptor):
    if "(" not in descriptor or ")" not in descriptor:
        raise ValueError(f"Invalid descriptor. {descriptor}")

    delimiter = descriptor.index(")")

    arg_str = descriptor[:delimiter]
    args = re.findall(r"L.+?;|[ZBCSIJFD]|\[", arg_str)

    new_descriptor = "(" + " ".join(args) + descriptor[delimiter:]
    new_descriptor = re.sub(r"\[ ", "[", new_descriptor)

    return new_descriptor


def filter_api_by_usage_count(data, api_pool, percentile_rank=0.2):
    """
    Sorting APIs by the number of APIs used in APK,
    and split APIs into P_set (less used number)
    and S_set (more used number)
    by percentile_rank (default 20%).

    :param data: the object of apkinfo.
    :param api_pool: the APIs list for rule generation.
    :param percentile_rank: the int for rank of percentile.
    :return P_set: a set of APIs that less used.
    :return S_set: a set of APIs that more used.
    """
    statistic_result = {}
    str_statistic_result = {}

    for api in api_pool:
        api_called_count = len(data.upperfunc(api))
        if api_called_count > 0:
            statistic_result[str(api)] = api_called_count
            str_statistic_result[str(api)] = api

    sorted_key = {
        k: v
        for k, v in sorted(statistic_result.items(), key=lambda item: item[1])
    }
    sorted_result = {k: v for k, v in sorted(sorted_key.items())}

    threshold = len(api_pool) * percentile_rank
    P_set = []
    S_set = []

    for i, (api, _) in enumerate(sorted_result.items()):
        if i < threshold:
            P_set.append(str_statistic_result[api])
            continue
        S_set.append(str_statistic_result[api])

    return P_set, S_set


def get_parenthetic_contents(string: str, start_index: int) -> str:
    """Get the content between a pair of parentheses.

    :param string: string to be parsed
    :param start_index: index to specify the parenthesis
    :return: string holding the content
    """
    start_index = string.find("(", start_index)
    if start_index == -1:
        return string

    parenthetic_counter = 0
    for idx, char in enumerate(string[start_index:]):
        if char == "(":
            parenthetic_counter += 1
        elif char == ")":
            parenthetic_counter -= 1

        if parenthetic_counter == 0:
            end_index = idx + start_index + 1
            return string[start_index:end_index]

    return string[start_index:]


def get_arguments_from_argument_str(
    argument_str: str, descriptor: str
) -> List[Any]:
    """Get arguments from an argument string.

    :param argument_str: string that holds multiple arguments and uses commas
     as separators
    :param descriptor: string that holds a descriptor for type inference
    :return: python list that holds the arguments
    """

    def __valueOf(argument: str, type_hint: str) -> Union[int, float, bool]:
        try:
            if type_hint in ["I", "B", "S", "J"]:
                return int(argument)
            elif type_hint == "Z":
                return bool(int(argument))
            elif type_hint in ["F", "D"]:
                return float(argument)
        except ValueError:
            pass

        return argument

    arguments = []

    parentheses_counter = 0
    index_of_last_separator = 0
    for index, char in enumerate(argument_str):
        if char == "(":
            parentheses_counter += 1
        elif char == ")":
            parentheses_counter -= 1
        elif char == "," and parentheses_counter == 0:
            arguments.append(argument_str[index_of_last_separator:index])
            index_of_last_separator = index + 1

    arguments.append(argument_str[index_of_last_separator:])

    type_hints = descriptor[1 : descriptor.find(")")].split()
    type_hints = reversed(type_hints)
    arguments = [
        __valueOf(argument, next(type_hints, ""))
        for argument in reversed(arguments)
    ]
    arguments.reverse()

    return arguments
