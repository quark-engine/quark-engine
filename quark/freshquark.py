import datetime
import os
import shutil

import click
import git

from quark.utils.colors import green
from quark.utils.out import print_success, print_warning, print_info

DIR_PATH = "quark-rules"
CHECK_UP_TO_DATE = ".up_to_date.quark"

SOURCE = "https://github.com/quark-engine/quark-rules"


def logger():
    # Write the current update time to file.
    with open(CHECK_UP_TO_DATE, "w") as cu_f:
        cu_f.write(datetime.date.today().isoformat())


def check_update():
    # Check if CHECK_UP_TO_DATE file exists and the time is match or not.
    if os.path.isfile(CHECK_UP_TO_DATE):
        with open(CHECK_UP_TO_DATE) as f:

            if f.readline() == datetime.date.today().isoformat():
                # Your quark-rules is already up to date
                return
            else:
                download()

    else:
        download()


def download():
    try:
        print_info(f"Download the latest rules from {SOURCE}")
        git.Repo.clone_from(url=SOURCE, to_path=DIR_PATH)
        print_success("Complete downloading the latest quark-rules")

    except git.GitCommandError as e:

        DIR_EXISTS = "destination path 'quark-rules' already exists"
        NETWORK_UNAVAILABLE = "unable to access"

        if DIR_EXISTS in e.stderr:

            print_warning("quark-rules directory already exists!")

            if click.confirm("Do you want to download again?", default=True):
                shutil.rmtree(DIR_PATH)
                download()

        if NETWORK_UNAVAILABLE in e.stderr:
            print_warning(f"Your network is currently unavailable, you can use {green('freshquark')} "
                          "to update the quark-rules later!\n")

    logger()


def entry_point():
    download()


if __name__ == "__main__":
    pass
