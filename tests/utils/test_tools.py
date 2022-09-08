import os
import re
import shutil
from subprocess import (  # nosec B404
    PIPE,
    CalledProcessError,
    check_output,
    run,
)
from unittest.mock import patch

import pytest
from quark import config
from quark.utils.tools import (
    _get_rizin_version,
    contains,
    descriptor_to_androguard_format,
    download_rizin,
    find_rizin_in_configuration_folder,
    find_rizin_in_PATH,
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

        return "v" + first_matched.group(0)
    except TimeoutError:
        assert False
    except CalledProcessError:
        assert False


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

    with patch("quark.utils.tools._execute_command") as mock:
        mock.side_effect = CalledProcessError(
            "1",
            "mock command",
            stderr="fatal: unable to access "
            + "'https://github.com/rizinorg/rizin/'.",
        )

        assert not download_rizin(target_path)


def test_fail_to_download_rizin_due_to_unknown_errors(tmp_path):
    target_path = tmp_path / "rizin"

    with patch("quark.utils.tools._execute_command") as mock:
        mock.side_effect = CalledProcessError("1", "mock command", stderr=b"")

        assert not download_rizin(target_path)


def test_update_rizin(tmp_path):
    target_path = tmp_path / "rizin"
    target_version_tag = config.COMPATIBLE_RAZIN_VERSIONS[0]

    download_rizin(target_path)

    update_rizin(target_path, target_version_tag)
    current_tag = (
        check_output(  # nosec
            ["git", "describe", "--tags"],
            cwd=target_path,
        )
        .decode()
        .strip()
    )

    assert current_tag == target_version_tag
    assert os.access(
        target_path / "build" / "binrz" / "rizin" / "rizin", os.F_OK | os.X_OK
    )


def test_fail_to_update_rizin_due_to_any_errors(tmp_path):
    target_path = tmp_path / "rizin"
    target_version_tag = config.COMPATIBLE_RAZIN_VERSIONS[0]

    with patch("subprocess.Popen") as mock:
        mock.side_effect = CalledProcessError(
            "1", "mock command", stderr=b"Error message"
        )

        assert not update_rizin(target_path, target_version_tag)


def test_find_rizin_in_path(rizin_in_system_path):
    rizin_path = find_rizin_in_PATH(config.COMPATIBLE_RAZIN_VERSIONS)
    assert rizin_path == rizin_in_system_path


def test_find_rizin_in_configuration_folder():
    expected_executable_path = config.RIZIN_DIR + "build/binrz/rizin/rizin"

    with patch("os.path.exists") as mocked_exists:
        mocked_exists.return_value = True

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            mocked_get_version.return_value = config.COMPATIBLE_RAZIN_VERSIONS[
                0
            ]

            executable_path, state = find_rizin_in_configuration_folder(
                config.COMPATIBLE_RAZIN_VERSIONS
            )

            assert executable_path == expected_executable_path
            assert state == "ready"
            mocked_get_version.assert_called_once_with(executable_path)


def test_find_outdated_rizin_in_configuration_directory():
    expected_executable_path = config.RIZIN_DIR + "build/binrz/rizin/rizin"

    with patch("os.path.exists") as mocked_exists:
        mocked_exists.return_value = True

        with patch(
            "quark.utils.tools._get_rizin_version"
        ) as mocked_get_version:
            mocked_get_version.return_value = "Outdated or broken version"

            executable_path, state = find_rizin_in_configuration_folder(
                config.COMPATIBLE_RAZIN_VERSIONS
            )

            assert executable_path == expected_executable_path
            assert state == "outdated"
            mocked_get_version.assert_called_once_with(executable_path)
