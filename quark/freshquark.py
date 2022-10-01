# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
"""
Freshquark is a command-line interface to download the latest Quark rules
"""

import os
import subprocess

from quark import config
from quark.utils.colors import green, yellow
from quark.utils.pprint import print_warning, print_info, print_success


def download():
    """
    Download the latest quark-rules from https://github.com/quark-engine/quark-rules.

    :return: None
    """

    if not os.path.isdir(config.DIR_PATH):

        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "https://github.com/quark-engine/quark-rules",
                    f"{config.HOME_DIR}quark-rules",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            if result.returncode == 0:
                # Download successful
                print_success("Complete downloading the latest quark-rules")

        except FileNotFoundError:

            print_warning("FileNotFoundError with git clone")

        except subprocess.CalledProcessError as error:

            network_unavailable = "unable to access"

            if network_unavailable in error.stderr.decode("utf-8"):
                print_warning(
                    f"Your network is currently unavailable, "
                    f"you can use {green('freshquark')} "
                    "to update the quark-rules later!\n"
                )
    else:
        try:
            result = subprocess.run(
                [
                    "git",
                    "-C",
                    f"{config.HOME_DIR}quark-rules",
                    "pull",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )

            if result.returncode == 0:
                # Download successful
                print_success(
                    f"Complete downloading the latest quark-rules.\n"
                    f"All the rules are saved in {yellow(config.DIR_PATH)}.\n"
                    f"To specify one of the rules of Quark-Rule, use "
                    f"{yellow(f'{config.DIR_PATH}/<rule_name>.json')} "
                    f"as an argument."
                )

        except subprocess.CalledProcessError as error:

            network_unavailable = "unable to access"

            if network_unavailable in error.stderr.decode("utf-8"):
                print_warning(
                    f"Your network is currently unavailable, "
                    f"you can use {green('freshquark')} "
                    "to update the quark-rules later!\n"
                )


def entry_point():
    """
    The command-line entry point for freshquark. It will download the latest quark-rules.

    :return: None
    """
    print_info(f"Download the latest rules from {config.SOURCE}")
    download()


if __name__ == "__main__":
    pass
