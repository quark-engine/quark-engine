import json
import hashlib


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def write_json_report(report_path, content):
    """
    Write file as json

    :param report_path: the path of report file
    :param content: content of the report
    :return: if write file succeed return True, otherwise return False
    """
    # Verify if content is dict
    if not isinstance(content, dict):
        return False

    # Write content as json file
    try:
        with open(report_path, "w+") as report_file:
            json.dump(content, report_file, indent=4)
    except OSError:
        return False

    report_file.close()

    return True


def hash_apk(apk):
    """
    Hash apk file

    :param apk: the path of the apk file
    :return hashed name of apk file
    """
    md5 = hashlib.md5()
    with open(apk, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()
