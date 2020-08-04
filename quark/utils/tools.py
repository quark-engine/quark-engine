import json
from filehash import FileHash


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def write_json_report(report_path, content):
    """
    Output reports in json format.

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
    Hash the apk file to get the MD5.

    :param apk: the path of the apk file
    :return hashed name of apk file
    """
    md5 = FileHash("md5")
    return md5.hash_file(apk)
