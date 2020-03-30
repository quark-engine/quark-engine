import logging
import sys
import tempfile

from quark.androguard.core.api_specific_resources import load_permission_mappings, load_permissions

log = logging.getLogger("androguard.default")


class InvalidResourceError(Exception):
    """
    Invalid Resource Erorr is thrown by load_api_specific_resource_module
    """
    pass


default_conf = {
    ## Configuration for executables used by androguard
    # Assume the binary is in $PATH, otherwise give full path
    "BIN_JADX": "jadx",
    # Dex2jar binary
    "BIN_DEX2JAR": "dex2jar.sh",

    # TODO Use apksigner instead
    "BIN_JARSIGNER": "jarsigner",  # TO BE REMOVED

    "BIN_DED": "ded.sh",  # TO BE REMOVED
    "BIN_JAD": "jad",  # TO BE REMOVED
    "BIN_WINEJAD": "jad.exe",  # TO BE REMOVED
    "BIN_FERNFLOWER": "fernflower.jar",  # TO BE REMOVED
    "OPTIONS_FERNFLOWER": {"dgs": '1',  # TO BE REMOVED
                           "asc": '1'},

    # Runtime variables
    #
    # A path to the temporary directory
    "TMP_DIRECTORY": tempfile.gettempdir(),

    # Function to print stuff
    "PRINT_FCT": sys.stdout.write,

    # Default API level, if requested API is not available
    "DEFAULT_API": 16,  # this is the minimal API version we have

    # Session, for persistence
    "SESSION": None,

}


class Configuration:
    instance = None

    def __init__(self):
        """
        A Wrapper for the CONF object
        This creates a singleton, which has the same attributes everywhere.
        """
        if not Configuration.instance:
            Configuration.instance = default_conf

    def __getattr__(self, item):
        return getattr(self.instance, item)

    def __getitem__(self, item):
        return self.instance[item]

    def __setitem__(self, key, value):
        self.instance[key] = value

    def __str__(self):
        return str(self.instance)

    def __repr__(self):
        return repr(self.instance)


CONF = Configuration()


def is_android_raw(raw):
    """
    Returns a string that describes the type of file, for common Android
    specific formats
    """
    val = None

    # We do not check for META-INF/MANIFEST.MF,
    # as you also want to analyze unsigned APKs...
    # AndroidManifest.xml should be in every APK.
    # classes.dex and resources.arsc are not required!
    # if raw[0:2] == b"PK" and b'META-INF/MANIFEST.MF' in raw:
    # TODO this check might be still invalid. A ZIP file with stored APK inside would match as well.
    # probably it would be better to rewrite this and add more sanity checks.
    if raw[0:2] == b"PK" and b'AndroidManifest.xml' in raw:
        val = "APK"
    elif raw[0:3] == b"dex":
        val = "DEX"
    elif raw[0:3] == b"dey":
        val = "DEY"
    elif raw[0:4] == b"\x03\x00\x08\x00" or raw[0:4] == b"\x00\x00\x08\x00":
        val = "AXML"
    elif raw[0:4] == b"\x02\x00\x0C\x00":
        val = "ARSC"

    return val


def load_api_specific_resource_module(resource_name, api=None):
    """
    Load the module from the JSON files and return a dict, which might be empty
    if the resource could not be loaded.

    If no api version is given, the default one from the CONF dict is used.

    :param resource_name: Name of the resource to load
    :param api: API version
    :return: dict
    """
    loader = dict(aosp_permissions=load_permissions,
                  api_permission_mappings=load_permission_mappings)

    if resource_name not in loader:
        raise InvalidResourceError("Invalid Resource '{}', not in [{}]".format(resource_name, ", ".join(loader.keys())))

    if not api:
        api = CONF["DEFAULT_API"]

    ret = loader[resource_name](api)

    if ret == {}:
        # No API mapping found, return default
        log.warning("API mapping for API level {} was not found! "
                    "Returning default, which is API level {}".format(api, CONF['DEFAULT_API']))
        ret = loader[resource_name](CONF['DEFAULT_API'])

    return ret
