import os
from filehash import FileHash

def remove_dup_list(element):
    """
    Remove the duplicate elements in  given list.
    """
    return list(set(element))

def output_json_report(name):
    """
    Output the json report as a json file and name it with given name
    """
    pass
def hash_apk(apk):
    """
    Hash apk name

    :param apk: the path of the apk file
    :return hashed name of apk file
    """
    sha512 = FileHash("sha512")
    return sha512.hash_file(apk)