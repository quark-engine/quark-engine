# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import datetime
import os
import shutil

import git

from quark import config
from quark.utils.colors import green
from quark.utils.out import print_warning, print_info, print_success

DIR_PATH = f"{config.HOME_DIR}quark-rules"
CHECK_UP_TO_DATE = f"{config.HOME_DIR}.up_to_date.quark"

SOURCE = "https://github.com/quark-engine/quark-rules"


def logger():
    """
    Write today's date into a file to record whether it has been updated on that day.

    :return: None
    """
    # Write the current update time to file.
    with open(CHECK_UP_TO_DATE, "w") as file:
        file.write(datetime.date.today().isoformat())


def check_update():
    """
    Check if the CHECK_UP_TO_DATE file exists and if the time matches,
    if it is not the latest, it will download the latest quark-rules.

    :return: None
    """
    if os.path.isfile(CHECK_UP_TO_DATE):
        with open(CHECK_UP_TO_DATE) as file:

            if file.readline() == datetime.date.today().isoformat():
                # quark-rules is already up to date with daily checks
                return

            download()

    else:
        download()


def download():
    """
    Download the latest quark-rules from https://github.com/quark-engine/quark-rules.

    :return: None
    """
    try:
        git.Repo.clone_from(url=SOURCE, to_path=DIR_PATH)

    except git.GitCommandError as error:

        dir_exists = "destination path"
        network_unavailable = "unable to access"

        if dir_exists in error.stderr:
            # remove the entire quark-rules directory and then clone again
            shutil.rmtree(DIR_PATH)
            download()

        if network_unavailable in error.stderr:
            print_warning(
                f"Your network is currently unavailable, "
                f"you can use {green('freshquark')} "
                "to update the quark-rules later!\n"
            )

    logger()


def entry_point():
    """
    The command-line entry point for freshquark. It will download the latest quark-rules.

    :return: None
    """
    print_info(f"Download the latest rules from {SOURCE}")
    download()
    print_success("Complete downloading the latest quark-rules")


if __name__ == "__main__":
    pass
