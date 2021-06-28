from unittest.mock import patch

from quark.freshquark import download


def test_download_without_exist_rules(tmp_path):
    non_exist_rule_directory = tmp_path / "quark-rules"

    with patch("quark.config.DIR_PATH", non_exist_rule_directory) as _:

        with patch("subprocess.run") as mock:
            download()

            mock.assert_called_once()
            assert set(mock.call_args[0][0]) == {
                "git",
                "clone",
                "https://github.com/quark-engine/quark-rules",
                non_exist_rule_directory,
            }


def test_download_with_exist_rules(tmp_path):
    exist_rule_directory = tmp_path / "quark-rules"
    exist_rule_directory.mkdir()

    with patch("quark.config.DIR_PATH", exist_rule_directory) as _:

        with patch("subprocess.run") as mock:
            download()

            mock.assert_called_once()
            assert mock.call_args[0][0] == [
                "git",
                "-C",
                exist_rule_directory,
                "pull",
            ]
