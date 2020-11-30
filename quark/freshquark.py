import shutil

import click
import git

from quark.utils.out import print_success, print_warning, print_info

DIR_PATH = "quark-rules"


def download():
    try:
        print_info("Download the latest rules from https://github.com/quark-engine/quark-rules")
        git.Repo.clone_from(url="https://github.com/quark-engine/quark-rules", to_path=DIR_PATH)
        print_success("Complete downloading the latest quark-rules")

    except git.GitCommandError:

        print_warning("quark-rules directory already exists!")

        if click.confirm("Do you want to download again?", default=True):
            shutil.rmtree(DIR_PATH)
            download()


def entry_point():
    download()


if __name__ == "__main__":
    pass
