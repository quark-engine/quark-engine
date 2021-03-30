# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
"""
Freshquark is a command-line interface to download the latest Quark rules
"""

import datetime
import os
import shutil
import stat
import subprocess

from quark import config
from quark.utils.colors import green
from quark.utils.out import print_warning, print_info, print_success


def set_rw(operation, name, exc):
    """
    A specific helper function to make the Windows Git directory deletable.

    :return: True
    """
    os.chmod(name, stat.S_IWRITE)
    return True


def logger():
    """
    Write today's date into a file to record whether it has been updated on that day.

    :return: None
    """
    # Write the current update time to file.
    with open(config.CHECK_UP_TO_DATE, "w") as file:
        file.write(datetime.date.today().isoformat())


def download():
    """
    Download the latest quark-rules from https://github.com/quark-engine/quark-rules.

    :return: None
    """
    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "https://github.com/quark-engine/quark-rules",
                config.DIR_PATH,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            # Download successful
            print_success("Complete downloading the latest quark-rules")

        else:
            # Download failed
            dir_exists = "destination path"
            network_unavailable = "unable to access"

            if dir_exists in result.stderr.decode("utf-8"):
                shutil.rmtree(config.DIR_PATH, onerror=set_rw)
                download()

            if network_unavailable in result.stderr.decode("utf-8"):
                print_warning(
                    f"Your network is currently unavailable, "
                    f"you can use {green('freshquark')} "
                    "to update the quark-rules later!\n"
                )

    except FileNotFoundError:

        print_warning("FileNotFoundError with git clone")

    except subprocess.CalledProcessError as error:

        print_warning(f"CalledProcessError with git clone, error: {error}")

    logger()


def entry_point():
    """
    The command-line entry point for freshquark. It will download the latest quark-rules.

    :return: None
    """
    print_info(f"Download the latest rules from {config.SOURCE}")
    download()


if __name__ == "__main__":
    pass
