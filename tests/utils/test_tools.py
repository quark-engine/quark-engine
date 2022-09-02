import os
import re
import shutil
from subprocess import PIPE, CalledProcessError, Popen, run
from sys import stderr  # nosec
from unittest.mock import patch

import pytest
from quark import config
from quark.utils.tools import (
    _get_rizin_version,
    contains,
    descriptor_to_androguard_format,
    download_rizin,
    find_rizin_instance,
    remove_dup_list,
    update_rizin,
)


@pytest.fixture(scope="module")
def rizin_in_system_path():
    path = shutil.which("rizin")
    assert path

    return path


@pytest.fixture(scope="module")
def version_of_rizin_installed_on_system():
    rizin_in_system_path = shutil.which("rizin")
    try:
        process = run(  # nosec
            [rizin_in_system_path, "-v"], timeout=5, check=True, stdout=PIPE
        )
        result = str(process.stdout)

        matched_versions = re.finditer(
            r"[0-9]+\.[0-9]+\.[0-9]+", result[: result.index("@")]
        )
        first_matched = next(matched_versions, None)

        assert first_matched

        return first_matched.group(0)
    except TimeoutError:
        assert False
    except CalledProcessError:
        assert False


@pytest.fixture(
    scope="function",
    params=((True), (False)),
)
def disable_rizin_installation(request):
    return request.param


def test_remove_dup_list_with_invalid_arg():
    with pytest.raises(TypeError):
        remove_dup_list(123)


def test_remove_dup_list_with_empty_list():
    assert remove_dup_list([]) == []


def test_remove_dup_list_with_numbers():
    assert remove_dup_list([1, 2, 3, 4, 3, 4, 2]) == [1, 2, 3, 4]


def test_remove_dup_list_with_strings():
    assert set(remove_dup_list(["hello", "test", "test"])) == {
        "hello",
        "test",
    }


def test_remove_dup_list_with_floats():
    assert remove_dup_list([2.0, 30, 4.0, 2.0]) == [2.0, 4.0, 30]


def test_contains_with_mutually_exclusive_list():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["put", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_superset():
    subset = ["put", "getCellLocation", "query", "sendTextMessage"]
    target = ["put", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_incorrect_sequence():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["sendTextMessage", "put", "getCellLocation", "query"]

    result = contains(subset, target)

    assert result is False


def test_contains_with_correct_sequence():
    subset = ["getCellLocation", "sendTextMessage"]
    target = ["put", "getCellLocation", "query", "sendTextMessage"]

    result = contains(subset, target)

    assert result is True


def test_descriptor_to_androguard_format_with_invalid_str():
    descriptor = "Z"

    with pytest.raises(ValueError):
        _ = descriptor_to_androguard_format(descriptor)


def test_descriptor_to_androguard_format_with_formatted_str():
    descriptor = "(I Ljava/lang/String; [B J)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == descriptor


def test_descriptor_to_androguard_format_with_primitive():
    descriptor = "(ZBCSIJFD)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(Z B C S I J F D)"


def test_descriptor_to_androguard_format_with_class():
    descriptor = "(Ljava/lang/String;)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(Ljava/lang/String;)"


def test_descriptor_to_androguard_format_with_array():
    descriptor = "([Ljava/lang/String;)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "([Ljava/lang/String;)"


def test_descriptor_to_androguard_format_with_combination():
    descriptor = "(ILjava/lang/String;[BJ)"

    result = descriptor_to_androguard_format(descriptor)

    assert result == "(I Ljava/lang/String; [B J)"


def test_get_rizin_version_with_valid_path(
    rizin_in_system_path, version_of_rizin_installed_on_system
):
    expected_version = version_of_rizin_installed_on_system

    found_version = _get_rizin_version(rizin_in_system_path)

    assert found_version == expected_version


def test_get_rizin_version_with_invalid_path(tmp_path):
    assert not _get_rizin_version(tmp_path)


def test_download_rizin_successfully(tmp_path):
    target_path = tmp_path / "rizin"

    with patch("quark.utils.tools._execute_command") as mock:        
        download_rizin(target_path)
        mock.assert_called_once()


def test_fail_to_download_rizin_due_to_unavailable_network(tmp_path):
    target_path = tmp_path / "rizin"

    with patch("subprocess.Popen.__new__") as mock:
        mock.side_effect = CalledProcessError(
            "1",
            "mock command",
            stderr="fatal: unable to access "
            + "'https://github.com/rizinorg/rizin/'.",
        )

        assert not download_rizin(target_path)


def test_fail_to_download_rizin_due_to_unknown_errors(tmp_path):
    target_path = tmp_path / "rizin"

    with patch("subprocess.Popen.__new__") as mock:
        mock.side_effect = CalledProcessError("1", "mock command", stderr=b"")

        assert not download_rizin(target_path)


def test_update_rizin(tmp_path):
    target_path = tmp_path / "rizin"
    target_commit = config.RIZIN_COMMIT

    download_rizin(target_path)

    update_rizin(target_path, target_commit)
    check_commit = run(  # nosec
        ["git", "rev-parse", "HEAD"],
        stdout=PIPE,
        stderr=PIPE,
        check=True,
        cwd=target_path,
    )
    real_commit = check_commit.stdout.strip().decode()

    assert real_commit == target_commit
    assert os.access(
        target_path / "build" / "binrz" / "rizin" / "rizin", os.F_OK | os.X_OK
    )


def test_fail_to_update_rizin_due_to_any_errors(tmp_path):
    target_path = tmp_path / "rizin"
    target_commit = config.RIZIN_COMMIT

    with patch("subprocess.Popen") as mock:
        mock.side_effect = CalledProcessError(
            "1", "mock command", stderr=b"Error message"
        )

        assert not update_rizin(target_path, target_commit)


def test_find_rizin_instance_in_system_path(rizin_in_system_path):
    rizin_path = find_rizin_instance()

    assert rizin_path == rizin_in_system_path


def test_find_rizin_instance_installed_in_quark_directory():
    rizin_source_path = "rizin_source_path"
    rizin_executable_path = rizin_source_path + "build/binrz/rizin/rizin"
    target_commit = "Unused"

    with patch("shutil.which") as mocked_which:
        # Pretend there is no Rizin instance installed in the system.
        mocked_which.return_value = None

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            # Pretend the Rizin instance installed in the Quark directory is
            # compatible.
            mocked_get_version.return_value = config.COMPATIBLE_RAZIN_VERSIONS[
                0
            ]

            # Must use the instance in the Quark directory.
            assert (
                find_rizin_instance(rizin_source_path, target_commit)
                == rizin_executable_path
            )

            # Must check the system path first.
            mocked_which.assert_called()
            # Must check the version of the instance in the Quark directory.
            mocked_get_version.assert_called()


def test_find_outdated_rizin_instance_installed_in_quark_directory(
    disable_rizin_installation,
):
    rizin_source_path = "rizin_source_path"
    rizin_executable_path = rizin_source_path + "build/binrz/rizin/rizin"
    target_commit = "Unused"

    with patch("shutil.which") as mocked_which:
        # Pretend there is no Rizin instance installed in the system.
        mocked_which.return_value = None

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            # Pretend the Rizin instance installed in the Quark directory is
            # not compatible.
            mocked_get_version.return_value = "0.0.0"

            with patch(
                "quark.utils.tools.update_rizin"
            ) as mocked_update_rizin:
                # Pretend the upgrade is finished successfully.
                mocked_update_rizin.return_value = True

                # Must use the instance in the Quark directory.
                assert (
                    find_rizin_instance(
                        rizin_source_path,
                        target_commit,
                        disable_rizin_installation,
                    )
                    == rizin_executable_path
                )

                # Must check the system path first.
                mocked_which.assert_called()
                # Must check the version of the instance in the Quark
                # directory.
                mocked_get_version.assert_called()
                if disable_rizin_installation:
                    # Must not update the instance
                    mocked_update_rizin.assert_not_called()
                else:
                    # Must update the instance to a compatible version
                    mocked_update_rizin.assert_called()


_compatible_trigger = None


def _side_effort_for_downloading_rizin(arg):
    global _compatible_trigger
    _compatible_trigger = True
    return True


def test_find_broken_rizin_instance_installed_in_quark_directory(
    disable_rizin_installation,
):
    rizin_source_path = "rizin_source_path"
    rizin_executable_path = rizin_source_path + "build/binrz/rizin/rizin"
    target_commit = "Unused"

    with patch("shutil.which") as mocked_which:
        # Pretend there is no Rizin instance installed in the system.
        mocked_which.return_value = "rizin_installed_in_system"

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            # Pretend -
            # 1. the Rizin instance in the system path is not compatible
            # 2. the Rizin instance in the Quark directory is broken.
            mocked_get_version.side_effect = (
                lambda x: "0.0.0"
                if x == "rizin_installed_in_system"
                else _compatible_trigger
            )

            with patch(
                "quark.utils.tools.download_rizin"
            ) as mocked_download_rizin:
                # Pretend we can download the source code successfully.
                mocked_download_rizin.side_effect = (
                    _side_effort_for_downloading_rizin
                )

                with patch(
                    "quark.utils.tools.update_rizin"
                ) as mocked_update_rizin:
                    # Pretend we can finish the upgrade successfully.
                    mocked_update_rizin.return_value = True

                    result = find_rizin_instance(
                        rizin_source_path,
                        target_commit,
                        disable_rizin_installation,
                    )
                    if disable_rizin_installation:
                        # No Rizin instance exists
                        assert result is None
                    else:
                        # Must use the instance in the Quark directory.
                        assert result == rizin_executable_path

                    # Must check the system path first.
                    mocked_which.assert_called()
                    # Must check the version of the instance in the Quark
                    # directory.
                    mocked_get_version.assert_called()

                    if disable_rizin_installation:
                        # Must not download the source code.
                        mocked_download_rizin.assert_not_called()
                        # Must not update and compile a Rizin instance.
                        mocked_update_rizin.assert_not_called()
                    else:
                        # Must download the source code.
                        mocked_download_rizin.assert_called()
                        # Must update and compile a Rizin instance.
                        mocked_update_rizin.assert_called()


def test_find_rizin_instance_failed_to_download_the_source():
    rizin_source_path = "rizin_source_path"
    target_commit = "Unused"

    with patch("shutil.which") as mocked_which:
        # Pretend there is no Rizin instance installed in the system.
        mocked_which.return_value = None

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            # Pretend the Rizin instance installed in the Quark directory is
            # broken.
            mocked_get_version.return_value = None

            with patch(
                "quark.utils.tools.download_rizin"
            ) as mocked_download_rizin:
                # Fail to download the source of Rizin.
                mocked_download_rizin.return_value = False

                # Must use the instance in the Quark directory.
                assert (
                    find_rizin_instance(rizin_source_path, target_commit)
                    is None
                )

                # Must check the system path first.
                mocked_which.assert_called()
                # Must check the version of the instance in the Quark
                # directory.
                mocked_get_version.assert_called()
                # Must try to download the source code of the Rizin.
                mocked_download_rizin.assert_called()


def test_find_rizin_instance_failed_to_compile_or_update_the_source():
    rizin_source_path = "rizin_source_path"
    target_commit = "Unused"

    with patch("shutil.which") as mocked_which:
        # Pretend there is no Rizin instance installed in the system.
        mocked_which.return_value = None

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            # Pretend the Rizin instance installed in the Quark directory is
            # not compatible.
            mocked_get_version.return_value = "0.0.0"

            with patch(
                "quark.utils.tools.update_rizin"
            ) as mocked_update_rizin:
                # Pretend the upgrade is finished successfully.
                mocked_update_rizin.return_value = False

                # Must use the instance in the Quark directory.
                assert (
                    find_rizin_instance(rizin_source_path, target_commit)
                    is None
                )

                # Must check the system path first.
                mocked_which.assert_called()
                # Must check the version of the instance in the Quark
                # directory.
                mocked_get_version.assert_called()
                # Must try to update and compile a Rizin instance.
                mocked_update_rizin.assert_called()
