# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import copy
import os.path
import re
import shutil
from os import F_OK, PathLike, access, mkdir
from subprocess import (  # nosec
    PIPE,
    STDOUT,
    CalledProcessError,
    Popen,
    check_output,
)
from typing import List, Tuple
from xmlrpc.client import Boolean

from click import confirm, prompt
from quark.config import COMPATIBLE_RAZIN_VERSIONS, RIZIN_DIR
from quark.utils.pprint import clear_the_last_line, print_error, print_info


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


def _execute_command(command, stderr=PIPE, cwd=None):
    """
    Execute a given command and yield the messages from the standard output.

    :param command: a list of strings which is the command to execute
    :param cwd: a PathLike object which is the working directory. Defaults to
    None
    :raises subprocess.CalledProcessError: if the process terminates with a
    non-zero return code
    :yield: a string holding a line of message in the standard output
    """
    process = Popen(  # nosec
        command,
        bufsize=1,
        stdout=PIPE,
        stderr=stderr,
        universal_newlines=True,
        cwd=cwd,
    )

    line = ""
    while True:
        char = process.stdout.read(1)
        if char == "\n" or char == "\r":
            clear_the_last_line()
            yield line
            line = ""
            continue

        elif char == "":
            break

        line = line + char

    process.stdout.close()
    return_code = process.wait()

    if return_code:
        error_messages = ""
        if stderr == PIPE:
            for message in process.stderr.readlines():
                error_messages = error_messages + message

        raise CalledProcessError(return_code, command, stderr=error_messages)

    if stderr == PIPE:
        process.stderr.close()


def _get_rizin_version(executable_path) -> str:
    """
    Get the version number of the Rizin instance in the path.

    :param rizin_path: a path to the Rizin executable
    :return: the version number of the Rizin instance
    """
    try:
        result = check_output([executable_path, "-v"], timeout=5)  # nosec
        result = str(result)

        matched_versions = re.finditer(
            r"[0-9]+\.[0-9]+\.[0-9]+", result[: result.index("@")]
        )
        first_matched = next(matched_versions, None)

        if first_matched:
            return "v" + first_matched.group(0)
        else:
            return None

    except CalledProcessError:
        return None

    except OSError:
        return None


def download_rizin(target_path) -> Boolean:
    """
    Download the source code of Rizin into the specified path. If a file or
    folder already exists, this function will remove them.

    :param target_path: a PathLike object specifying the location to save the
    downloaded files
    :return: a boolean indicating if the operation finishes without errors
    """
    if access(target_path, F_OK):
        shutil.rmtree(target_path)
        mkdir(target_path)

    try:
        print()

        for line in _execute_command(
            [
                "git",
                "clone",
                "--progress",
                "https://github.com/rizinorg/rizin",
                target_path,
            ],
            stderr=STDOUT,
        ):
            print_info(line)

        return True

    except CalledProcessError:
        print_error("An error occurred when downloading Rizin.\n")

    except OSError:
        print_error("An error occurred when downloading Rizin.\n")

    return False


def update_rizin(source_path, tag) -> bool:
    """
    Checkout the specified commit in the Rizin repository. Then, compile the
    source code to build a Rizin executable.

    :param source_path: a PathLike object specifying the location to the
    source code
    :param target_commit: a hash value representing a valid commit in the
    repository
    :return: a boolean indicating the operation is success or not
    """

    def _print_error(error: CalledProcessError):
        error_output = error.stderr
        if isinstance(error_output, (bytes, bytearray)):
            error_output = error_output.decode()

        for line in error_output.splitlines():
            print_error(line)

    try:
        print()

        # Checkout to target commit
        for line in _execute_command(
            ["git", "checkout", tag], cwd=source_path
        ):
            print_info(line)

        # Remove the last build
        for line in _execute_command(["rm", "-rf", "build"], cwd=source_path):
            print_info(line)

        # Clean out old subprojects
        for line in _execute_command(
            ["git", "clean", "-dxff", "subprojects/"], cwd=source_path
        ):
            print_info(line)

    except CalledProcessError as error:
        _print_error(error)
        return False

    except OSError as error:
        print_error("An error occurred when updating Rizin.\n")
        print_error(error)
        return False

    # Compile Rizin
    try:
        print()

        # Configure
        for line in _execute_command(
            ["meson", "--buildtype=release", "build"], cwd=source_path
        ):
            print_info(line)

        # Compile the source code
        for line in _execute_command(
            ["meson", "compile", "-C", "build"], cwd=source_path
        ):
            print_info(line)

        return True

    except CalledProcessError as error:
        _print_error(error)

    except OSError as error:
        print_error("an error occurred when building rizin.\n")
        print_error(error)

    return False


def find_rizin_in_PATH(compatible_versions: List[str]) -> PathLike:
    """Search the system variable, PATH, to find an appropriate Rizin
     executable.

    :param compatible_versions: python list containing compatible Rizin
     versions
    :return: path to the Rizin executable
    """
    executable_path = shutil.which("rizin")
    if executable_path:
        version = _get_rizin_version(executable_path)
        if version in compatible_versions:
            return executable_path


def find_rizin_in_configuration_folder(
    compatible_versions: List[str],
) -> Tuple[str, str]:
    """Search the configuration folder of Quark (~/.quark-engine) to find
     an appropriate Rizin executable.

    :param compatible_versions: python list containing compatible Rizin
     versions
    :return: path to the Rizin executable
    """
    executable_path = RIZIN_DIR + "build/binrz/rizin/rizin"
    if os.path.exists(executable_path):
        version = _get_rizin_version(executable_path)
        if version in compatible_versions:
            return executable_path, "ready"
        else:
            return executable_path, "outdated"

    return None, "Not found"


def find_rizin() -> PathLike:
    """
    Search the system PATH and the configuration folder of Quark
     (~/.quark-engine) to find an appropriate Rizin executable. If none of them
      are usable, this method will ask users to specify one.

    :return: path to an Rizin executable
    """

    compatible_versions = COMPATIBLE_RAZIN_VERSIONS
    recommend_version = compatible_versions[0]

    # Search Rizin in Path
    executable_path = find_rizin_in_PATH(compatible_versions)
    if executable_path:
        return executable_path

    # Otherwise, search the configuration folder of Quark
    executable_path, state = find_rizin_in_configuration_folder(
        compatible_versions
    )
    if executable_path:
        if state == "outdated":
            update_rizin(RIZIN_DIR, recommend_version)
            return executable_path
        elif state == "ready":
            return executable_path

    # Ask if the user is willing to install Rizin
    install_rizin = confirm(
        f"Do you want to install Rizin {recommend_version}?", show_default=True
    )
    if install_rizin:
        # download_rizin(RIZIN_DIR)
        update_rizin(RIZIN_DIR, recommend_version)

        return os.path.join(RIZIN_DIR, "build", "binrz", "rizin", "rizin")

    # Otherwise, ask for the path to a Rizin executable
    executable_path = prompt("Please specify a path to the Rizin executable")
    return executable_path
