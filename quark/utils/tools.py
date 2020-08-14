import hashlib


def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))


def get_apk_md5(apk):
    """
    Return hashed md5 checksum for apk file.

    :param apk: the path of the apk file.
    :return: String of md5 checksum for hashed apk file.
    """
    md5 = hashlib.md5()
    with open(apk, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()
