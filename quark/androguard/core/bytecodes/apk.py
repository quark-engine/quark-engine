from quark.androguard.core import androconf
from quark.androguard.util import read, get_certificate_name_string

from quark.androguard.core.bytecodes.axml import ARSCParser, AXMLPrinter, ARSCResTableConfig, AXMLParser, format_value, \
    START_TAG, END_TAG, TEXT, END_DOCUMENT

import io
from zlib import crc32
import os
import re
import binascii
import zipfile
import logging
from struct import unpack
import hashlib
import warnings

import lxml.sax
from xml.dom.pulldom import SAX2DOM

# Used for reading Certificates
from asn1crypto import cms, x509, keys

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)  # Namespace as used by etree

log = logging.getLogger("androguard.apk")


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class FileNotPresent(Error):
    pass


class BrokenAPKError(Error):
    pass


def _dump_additional_attributes(additional_attributes):
    """ try to parse additional attributes, but ends up to hexdump if the scheme is unknown """

    attributes_raw = io.BytesIO(additional_attributes)
    attributes_hex = binascii.hexlify(additional_attributes)

    if not len(additional_attributes):
        return attributes_hex

    len_attribute, = unpack('<I', attributes_raw.read(4))
    if len_attribute != 8:
        return attributes_hex

    attr_id, = unpack('<I', attributes_raw.read(4))
    if attr_id != APK._APK_SIG_ATTR_V2_STRIPPING_PROTECTION:
        return attributes_hex

    scheme_id, = unpack('<I', attributes_raw.read(4))

    return "stripping protection set, scheme %d" % scheme_id


def _dump_digests_or_signatures(digests_or_sigs):
    infos = ""
    for i, dos in enumerate(digests_or_sigs):
        infos += "\n"
        infos += " [%d]\n" % i
        infos += "  - Signature Id : %s\n" % APK._APK_SIG_ALGO_IDS.get(dos[0], hex(dos[0]))
        infos += "  - Digest: %s" % binascii.hexlify(dos[1])

    return infos


class APKV2SignedData:
    """ 
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.digests = None
        self.certificates = None
        self.additional_attributes = None

    def __str__(self):
        certs_infos = ""

        for i, cert in enumerate(self.certificates):
            x509_cert = x509.Certificate.load(cert)

            certs_infos += "\n"
            certs_infos += " [%d]\n" % i
            certs_infos += "  - Issuer: %s\n" % get_certificate_name_string(x509_cert.issuer, short=True)
            certs_infos += "  - Subject: %s\n" % get_certificate_name_string(x509_cert.subject, short=True)
            certs_infos += "  - Serial Number: %s\n" % hex(x509_cert.serial_number)
            certs_infos += "  - Hash Algorithm: %s\n" % x509_cert.hash_algo
            certs_infos += "  - Signature Algorithm: %s\n" % x509_cert.signature_algo
            certs_infos += "  - Valid not before: %s\n" % x509_cert['tbs_certificate']['validity']['not_before'].native
            certs_infos += "  - Valid not after: %s" % x509_cert['tbs_certificate']['validity']['not_after'].native

        return "\n".join([
            'additional_attributes : {}'.format(_dump_additional_attributes(self.additional_attributes)),
            'digests : {}'.format(_dump_digests_or_signatures(self.digests)),
            'certificates : {}'.format(certs_infos),
        ])


class APKV3SignedData(APKV2SignedData):
    """ 
    This class holds all data associated with an APK V3 SigningBlock signed data.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):
        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


class APKV2Signer:
    """ 
    This class holds all data associated with an APK V2 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v2.html
    """

    def __init__(self):
        self._bytes = None
        self.signed_data = None
        self.signatures = None
        self.public_key = None

    def __str__(self):
        return "\n".join([
            '{:s}'.format(str(self.signed_data)),
            'signatures : {}'.format(_dump_digests_or_signatures(self.signatures)),
            'public key : {}'.format(binascii.hexlify(self.public_key)),
        ])


class APKV3Signer(APKV2Signer):
    """ 
    This class holds all data associated with an APK V3 SigningBlock signer.
    source : https://source.android.com/security/apksigning/v3.html
    """

    def __init__(self):
        super().__init__()
        self.minSDK = None
        self.maxSDK = None

    def __str__(self):
        base_str = super().__str__()

        # maxSDK is set to a negative value if there is no upper bound on the sdk targeted
        max_sdk_str = "%d" % self.maxSDK
        if self.maxSDK >= 0x7fffffff:
            max_sdk_str = "0x%x" % self.maxSDK

        return "\n".join([
            'signer minSDK : {:d}'.format(self.minSDK),
            'signer maxSDK : {:s}'.format(max_sdk_str),
            base_str
        ])


class APK:
    # Constants in ZipFile
    _PK_END_OF_CENTRAL_DIR = b"\x50\x4b\x05\x06"
    _PK_CENTRAL_DIR = b"\x50\x4b\x01\x02"

    # Constants in the APK Signature Block
    _APK_SIG_MAGIC = b"APK Sig Block 42"
    _APK_SIG_KEY_V2_SIGNATURE = 0x7109871a
    _APK_SIG_KEY_V3_SIGNATURE = 0xf05368c0
    _APK_SIG_ATTR_V2_STRIPPING_PROTECTION = 0xbeeff00d

    _APK_SIG_ALGO_IDS = {
        0x0101: "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc",
        0x0102: "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc",
        0x0103: "RSASSA-PKCS1-v1_5 with SHA2-256 digest.",
        # This is for build systems which require deterministic signatures.
        0x0104: "RSASSA-PKCS1-v1_5 with SHA2-512 digest.",
        # This is for build systems which require deterministic signatures.
        0x0201: "ECDSA with SHA2-256 digest",
        0x0202: "ECDSA with SHA2-512 digest",
        0x0301: "DSA with SHA2-256 digest",
    }

    __no_magic = False

    def __init__(self, filename, raw=False, magic_file=None, skip_analysis=False, testzip=False):
        """
        This class can access to all elements in an APK file

        example::

            APK("myfile.apk")
            APK(read("myfile.apk"), raw=True)

        :param filename: specify the path of the file, or raw data
        :param raw: specify if the filename is a path or raw data (optional)
        :param magic_file: specify the magic file (not used anymore - legacy only)
        :param skip_analysis: Skip the analysis, e.g. no manifest files are read. (default: False)
        :param testzip: Test the APK for integrity, e.g. if the ZIP file is broken. Throw an exception on failure (default False)

        :type filename: string
        :type raw: boolean
        :type magic_file: string
        :type skip_analysis: boolean
        :type testzip: boolean

        """
        if magic_file:
            log.warning("You set magic_file but this parameter is actually unused. You should remove it.")

        self.filename = filename

        self.xml = {}
        self.axml = {}
        self.arsc = {}

        self.package = ""
        self.androidversion = {}
        self.permissions = []
        self.uses_permissions = []
        self.declared_permissions = {}
        self.valid_apk = False

        self._is_signed_v2 = None
        self._is_signed_v3 = None
        self._v2_blocks = {}
        self._v2_signing_data = None
        self._v3_signing_data = None

        self._files = {}
        self.files_crc32 = {}

        if raw is True:
            self.__raw = bytearray(filename)
            self._sha256 = hashlib.sha256(self.__raw).hexdigest()
            # Set the filename to something sane
            self.filename = "raw_apk_sha256:{}".format(self._sha256)
        else:
            self.__raw = bytearray(read(filename))

        self.zip = zipfile.ZipFile(io.BytesIO(self.__raw), mode="r")

        if testzip:
            log.info("Testing zip file integrity, this might take a while...")
            # Test the zipfile for integrity before continuing.
            # This process might be slow, as the whole file is read.
            # Therefore it is possible to enable it as a separate feature.
            #
            # A short benchmark showed, that testing the zip takes about 10 times longer!
            # e.g. normal zip loading (skip_analysis=True) takes about 0.01s, where
            # testzip takes 0.1s!
            ret = self.zip.testzip()
            if ret is not None:
                # we could print the filename here, but there are zip which are so broken
                # That the filename is either very very long or does not make any sense.
                # Thus we do not do it, the user might find out by using other tools.
                raise BrokenAPKError("The APK is probably broken: testzip returned an error.")

        if not skip_analysis:
            self._apk_analysis()

    @staticmethod
    def _ns(name):
        """
        return the name including the Android namespace URI
        """
        return NS_ANDROID + name

    def _apk_analysis(self):
        """
        Run analysis on the APK file.

        This method is usually called by __init__ except if skip_analysis is False.
        It will then parse the AndroidManifest.xml and set all fields in the APK class which can be
        extracted from the Manifest.
        """
        i = "AndroidManifest.xml"
        log.info("Starting analysis on {}".format(i))
        try:
            manifest_data = self.zip.read(i)
        except KeyError:
            log.warning("Missing AndroidManifest.xml. Is this an APK file?")
        else:
            ap = AXMLPrinter(manifest_data)

            if not ap.is_valid():
                log.error("Error while parsing AndroidManifest.xml - is the file valid?")
                return

            self.axml[i] = ap
            self.xml[i] = self.axml[i].get_xml_obj()

            if self.axml[i].is_packed():
                log.warning("XML Seems to be packed, operations on the AndroidManifest.xml might fail.")

            if self.xml[i] is not None:
                if self.xml[i].tag != "manifest":
                    log.error("AndroidManifest.xml does not start with a <manifest> tag! Is this a valid APK?")
                    return

                self.package = self.get_attribute_value("manifest", "package")
                self.androidversion["Code"] = self.get_attribute_value("manifest", "versionCode")
                self.androidversion["Name"] = self.get_attribute_value("manifest", "versionName")
                permission = list(self.get_all_attribute_value("uses-permission", "name"))
                self.permissions = list(set(self.permissions + permission))

                for uses_permission in self.find_tags("uses-permission"):
                    self.uses_permissions.append([
                        self.get_value_from_tag(uses_permission, "name"),
                        self._get_permission_maxsdk(uses_permission)
                    ])

                # getting details of the declared permissions
                for d_perm_item in self.find_tags('permission'):
                    d_perm_name = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "name")))
                    d_perm_label = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "label")))
                    d_perm_description = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "description")))
                    d_perm_permissionGroup = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "permissionGroup")))
                    d_perm_protectionLevel = self._get_res_string_value(
                        str(self.get_value_from_tag(d_perm_item, "protectionLevel")))

                    d_perm_details = {
                        "label": d_perm_label,
                        "description": d_perm_description,
                        "permissionGroup": d_perm_permissionGroup,
                        "protectionLevel": d_perm_protectionLevel,
                    }
                    self.declared_permissions[d_perm_name] = d_perm_details

                self.valid_apk = True
                log.info("APK file was successfully validated!")

        self.permission_module = androconf.load_api_specific_resource_module(
            "aosp_permissions", self.get_target_sdk_version())

    def __getstate__(self):
        """
        Function for pickling APK Objects.

        We remove the zip from the Object, as it is not pickable
        And it does not make any sense to pickle it anyways.

        :returns: the picklable APK Object without zip.
        """
        # Upon pickling, we need to remove the ZipFile
        x = self.__dict__
        x['axml'] = str(x['axml'])
        x['xml'] = str(x['xml'])
        del x['zip']

        return x

    def __setstate__(self, state):
        """
        Load a pickled APK Object and restore the state

        We load the zip file back by reading __raw from the Object.

        :param state: pickled state
        """
        self.__dict__ = state

        self.zip = zipfile.ZipFile(io.BytesIO(self.__raw), mode="r")

    def _get_res_string_value(self, string):
        if not string.startswith('@string/'):
            return string
        string_key = string[9:]

        res_parser = self.get_android_resources()
        if not res_parser:
            return ''
        string_value = ''
        for package_name in res_parser.get_packages_names():
            extracted_values = res_parser.get_string(package_name, string_key)
            if extracted_values:
                string_value = extracted_values[1]
                break
        return string_value

    def _get_permission_maxsdk(self, item):
        maxSdkVersion = None
        try:
            maxSdkVersion = int(self.get_value_from_tag(item, "maxSdkVersion"))
        except ValueError:
            log.warning(self.get_max_sdk_version() + 'is not a valid value for <uses-permission> maxSdkVersion')
        except TypeError:
            pass
        return maxSdkVersion

    def get_files(self):
        """
        Return the file names inside the APK.

        :rtype: a list of :class:`str`
        """
        return self.zip.namelist()

    def _get_file_magic_name(self, buffer):
        """
        Return the filetype guessed for a buffer
        :param buffer: bytes
        :returns: str of filetype
        """
        default = "Unknown"

        # Faster way, test once, return default.
        if self.__no_magic:
            return default

        try:
            # Magic is optional
            import magic
        except ImportError:
            self.__no_magic = True
            log.warning("No Magic library was found on your system.")
            return default
        except TypeError as e:
            self.__no_magic = True
            log.warning("It looks like you have the magic python package installed but not the magic library itself!")
            log.warning("Error from magic library: %s", e)
            log.warning(
                "Please follow the installation instructions at https://github.com/ahupp/python-magic/#installation")
            log.warning("You can also install the 'python-magic-bin' package on Windows and MacOS")
            return default

        try:
            # There are several implementations of magic,
            # unfortunately all called magic
            # We use this one: https://github.com/ahupp/python-magic/
            # You can also use python-magic-bin on Windows or MacOS
            getattr(magic, "MagicException")
        except AttributeError:
            self.__no_magic = True
            log.warning("Not the correct Magic library was found on your "
                        "system. Please install python-magic or python-magic-bin!")
            return default

        try:
            # 1024 byte are usually enough to test the magic
            ftype = magic.from_buffer(buffer[:1024])
        except magic.MagicException as e:
            log.exception("Error getting the magic type: %s", e)
            return default

        if not ftype:
            return default
        else:
            return self._patch_magic(buffer, ftype)

    @property
    def files(self):
        """
        Returns a dictionary of filenames and detected magic type

        :returns: dictionary of files and their mime type
        """
        return self.get_files_types()

    def get_files_types(self):
        """
        Return the files inside the APK with their associated types (by using python-magic)

        At the same time, the CRC32 are calculated for the files.

        :rtype: a dictionnary
        """
        if self._files == {}:
            # Generate File Types / CRC List
            for i in self.get_files():
                buffer = self._get_crc32(i)
                self._files[i] = self._get_file_magic_name(buffer)

        return self._files

    def _patch_magic(self, buffer, orig):
        """
        Overwrite some probably wrong detections by mime libraries

        :param buffer: bytes of the file to detect
        :param orig: guess by mime libary
        :returns: corrected guess
        """
        if ("Zip" in orig) or ('(JAR)' in orig) and androconf.is_android_raw(buffer) == 'APK':
            return "Android application package file"

        return orig

    def _get_crc32(self, filename):
        """
        Calculates and compares the CRC32 and returns the raw buffer.

        The CRC32 is added to `files_crc32` dictionary, if not present.

        :param filename: filename inside the zipfile
        :rtype: bytes
        """
        buffer = self.zip.read(filename)
        if filename not in self.files_crc32:
            self.files_crc32[filename] = crc32(buffer)
            if self.files_crc32[filename] != self.zip.getinfo(filename).CRC:
                log.error("File '{}' has different CRC32 after unpacking! "
                          "Declared: {:08x}, Calculated: {:08x}".format(filename,
                                                                        self.zip.getinfo(filename).CRC,
                                                                        self.files_crc32[filename]))
        return buffer

    def get_raw(self):
        """
        Return raw bytes of the APK

        :rtype: bytes
        """
        return self.__raw

    def get_file(self, filename):
        """
        Return the raw data of the specified filename
        inside the APK

        :rtype: bytes
        """
        try:
            return self.zip.read(filename)
        except KeyError:
            raise FileNotPresent(filename)

    def get_dex(self):
        """
        Return the raw data of the classes dex file

        This will give you the data of the file called `classes.dex`
        inside the APK. If the APK has multiple DEX files, you need to use :func:`~APK.get_all_dex`.

        :rtype: bytes
        """
        try:
            return self.get_file("classes.dex")
        except FileNotPresent:
            # TODO is this a good idea to return an empty string?
            return b""

    def get_dex_names(self):
        """
        Return the names of all DEX files found in the APK.
        This method only accounts for "offical" dex files, i.e. all files
        in the root directory of the APK named classes.dex or classes[0-9]+.dex

        :rtype: a list of str
        """
        dexre = re.compile(r"classes(\d*).dex")
        return filter(lambda x: dexre.match(x), self.get_files())

    def get_all_dex(self):
        """
        Return the raw data of all classes dex files

        :rtype: a generator of bytes
        """
        for dex_name in self.get_dex_names():
            yield self.get_file(dex_name)

    def _format_value(self, value):
        """
        Format a value with packagename, if not already set.
        For example, the name :code:`'.foobar'` will be transformed into :code:`'package.name.foobar'`.

        Names which do not contain any dots are assumed to be packagename-less as well:
        :code:`foobar` will also transform into :code:`package.name.foobar`.

        :param value:
        :returns:
        """
        if value and self.package:
            v_dot = value.find(".")
            if v_dot == 0:
                # Dot at the start
                value = self.package + value
            elif v_dot == -1:
                # Not a single dot
                value = self.package + "." + value
        return value

    def get_all_attribute_value(
            self, tag_name, attribute, format_value=True, **attribute_filter
    ):
        """
        Yields all the attribute values in xml files which match with the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """
        tags = self.find_tags(tag_name, **attribute_filter)
        for tag in tags:
            value = tag.get(attribute) or tag.get(self._ns(attribute))
            if value is not None:
                if format_value:
                    yield self._format_value(value)
                else:
                    yield value

    def get_attribute_value(
            self, tag_name, attribute, format_value=False, **attribute_filter
    ):
        """
        Return the attribute value in xml files which matches the tag name and the specific attribute

        :param str tag_name: specify the tag name
        :param str attribute: specify the attribute
        :param bool format_value: specify if the value needs to be formatted with packagename
        """

        for value in self.get_all_attribute_value(
                tag_name, attribute, format_value, **attribute_filter):
            if value is not None:
                return value

    def get_value_from_tag(self, tag, attribute):
        """
        Return the value of the android prefixed attribute in a specific tag.

        This function will always try to get the attribute with a android: prefix first,
        and will try to return the attribute without the prefix, if the attribute could not be found.
        This is useful for some broken AndroidManifest.xml, where no android namespace is set,
        but could also indicate malicious activity (i.e. wrongly repackaged files).
        A warning is printed if the attribute is found without a namespace prefix.

        If you require to get the exact result you need to query the tag directly:

        example::
            >>> from lxml.etree import Element
            >>> tag = Element('bar', nsmap={'android': 'http://schemas.android.com/apk/res/android'})
            >>> tag.set('{http://schemas.android.com/apk/res/android}foobar', 'barfoo')
            >>> tag.set('name', 'baz')
            # Assume that `a` is some APK object
            >>> a.get_value_from_tag(tag, 'name')
            'baz'
            >>> tag.get('name')
            'baz'
            >>> tag.get('foobar')
            None
            >>> a.get_value_from_tag(tag, 'foobar')
            'barfoo'

        :param lxml.etree.Element tag: specify the tag element
        :param str attribute: specify the attribute name
        :returns: the attribute's value, or None if the attribute is not present
        """

        # TODO: figure out if both android:name and name tag exist which one to give preference:
        # currently we give preference for the namespace one and fallback to the un-namespaced
        value = tag.get(self._ns(attribute))
        if value is None:
            value = tag.get(attribute)

            if value:
                # If value is still None, the attribute could not be found, thus is not present
                log.warning("Failed to get the attribute '{}' on tag '{}' with namespace. "
                            "But found the same attribute without namespace!".format(attribute, tag.tag))
        return value

    def find_tags(self, tag_name, **attribute_filter):
        """
        Return a list of all the matched tags in all available xml

        :param str tag: specify the tag name
        """
        all_tags = [
            self.find_tags_from_xml(
                i, tag_name, **attribute_filter
            )
            for i in self.xml
        ]
        return [tag for tag_list in all_tags for tag in tag_list]

    def find_tags_from_xml(
            self, xml_name, tag_name, **attribute_filter
    ):
        """
        Return a list of all the matched tags in a specific xml
        w
        :param str xml_name: specify from which xml to pick the tag from
        :param str tag_name: specify the tag name
        """
        xml = self.xml[xml_name]
        if xml is None:
            return []
        if xml.tag == tag_name:
            if self.is_tag_matched(
                    xml.tag, **attribute_filter
            ):
                return [xml]
            return []
        tags = xml.findall(".//" + tag_name)
        return [
            tag for tag in tags if self.is_tag_matched(
                tag, **attribute_filter
            )
        ]

    def is_tag_matched(self, tag, **attribute_filter):
        r"""
        Return true if the attributes matches in attribute filter.

        An attribute filter is a dictionary containing: {attribute_name: value}.
        This function will return True if and only if all attributes have the same value.
        This function allows to set the dictionary via kwargs, thus you can filter like this:

        example::
            a.is_tag_matched(tag, name="foobar", other="barfoo")

        This function uses a fallback for attribute searching. It will by default use
        the namespace variant but fall back to the non-namespace variant.
        Thus specifiying :code:`{"name": "foobar"}` will match on :code:`<bla name="foobar" \>`
        as well as on :code:`<bla android:name="foobar" \>`.

        :param lxml.etree.Element tag: specify the tag element
        :param attribute_filter: specify the attribute filter as dictionary
        """
        if len(attribute_filter) <= 0:
            return True
        for attr, value in attribute_filter.items():
            _value = self.get_value_from_tag(tag, attr)
            if _value != value:
                return False
        return True

    def get_main_activities(self):
        """
        Return names of the main activities

        These values are read from the AndroidManifest.xml

        :rtype: a set of str
        """
        x = set()
        y = set()

        for i in self.xml:
            if self.xml[i] is None:
                continue
            activities_and_aliases = self.xml[i].findall(".//activity") + \
                                     self.xml[i].findall(".//activity-alias")

            for item in activities_and_aliases:
                # Some applications have more than one MAIN activity.
                # For example: paid and free content
                activityEnabled = item.get(self._ns("enabled"))
                if activityEnabled == "false":
                    continue

                for sitem in item.findall(".//action"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.action.MAIN":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            x.add(item.get(self._ns("name")))
                        else:
                            log.warning('Main activity without name')

                for sitem in item.findall(".//category"):
                    val = sitem.get(self._ns("name"))
                    if val == "android.intent.category.LAUNCHER":
                        activity = item.get(self._ns("name"))
                        if activity is not None:
                            y.add(item.get(self._ns("name")))
                        else:
                            log.warning('Launcher activity without name')

        return x.intersection(y)

    def get_main_activity(self):
        """
        Return the name of the main activity

        This value is read from the AndroidManifest.xml

        :rtype: str
        """
        activities = self.get_main_activities()
        if len(activities) > 0:
            return self._format_value(activities.pop())
        return None

    def get_activities(self):
        """
        Return the android:name attribute of all activities

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("activity", "name"))

    def get_services(self):
        """
        Return the android:name attribute of all services

        :rtype: a list of str
        """
        return list(self.get_all_attribute_value("service", "name"))

    def get_receivers(self):
        """
        Return the android:name attribute of all receivers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("receiver", "name"))

    def get_providers(self):
        """
        Return the android:name attribute of all providers

        :rtype: a list of string
        """
        return list(self.get_all_attribute_value("provider", "name"))

    def get_res_value(self, name):
        """
        Return the literal value with a resource id

        :rtype: str 
        """

        res_parser = self.get_android_resources()
        if not res_parser:
            return name

        res_id = res_parser.parse_id(name)[0]
        try:
            value = res_parser.get_resolved_res_configs(
                res_id,
                ARSCResTableConfig.default_config())[0][1]
        except Exception as e:
            log.warning("Exception get resolved resource id: %s" % e)
            return name

        return value

    def get_intent_filters(self, itemtype, name):
        """
        Find intent filters for a given item and name.

        Intent filter are attached to activities, services or receivers.
        You can search for the intent filters of such items and get a dictionary of all
        attached actions and intent categories.

        :param itemtype: the type of parent item to look for, e.g. `activity`,  `service` or `receiver`
        :param name: the `android:name` of the parent item, e.g. activity name
        :returns: a dictionary with the keys `action` and `category` containing the `android:name` of those items
        """
        attributes = {"action": ["name"], "category": ["name"],
                      "data": ['scheme', 'host', 'port', 'path', 'pathPattern', 'pathPrefix', 'mimeType']}

        d = {}
        for element in attributes.keys():
            d[element] = []

        for i in self.xml:
            # TODO: this can probably be solved using a single xpath
            for item in self.xml[i].findall(".//" + itemtype):
                if self._format_value(item.get(self._ns("name"))) == name:
                    for sitem in item.findall(".//intent-filter"):
                        for element in d.keys():
                            for ssitem in sitem.findall(element):
                                if element == 'data':  # multiple attributes
                                    values = {}
                                    for attribute in attributes[element]:
                                        value = ssitem.get(self._ns(attribute))
                                        if value:
                                            if value.startswith('@'):
                                                value = self.get_res_value(value)
                                            values[attribute] = value

                                    if values:
                                        d[element].append(values)
                                else:
                                    for attribute in attributes[element]:
                                        value = ssitem.get(self._ns(attribute))
                                        if value.startswith('@'):
                                            value = self.get_res_value(value)

                                        if value not in d[element]:
                                            d[element].append(value)

        for element in list(d.keys()):
            if not d[element]:
                del d[element]

        return d

    def get_permissions(self):
        """
        Return permissions names declared in the AndroidManifest.xml.

        It is possible that permissions are returned multiple times,
        as this function does not filter the permissions, i.e. it shows you
        exactly what was defined in the AndroidManifest.xml.

        Implied permissions, which are granted automatically, are not returned
        here. Use :meth:`get_uses_implied_permission_list` if you need a list
        of implied permissions.

        :returns: A list of permissions
        :rtype: list
        """
        return self.permissions

    def get_declared_permissions(self):
        """
        Returns list of the declared permissions.

        :rtype: list of strings
        """
        return list(self.declared_permissions.keys())

    def get_max_sdk_version(self):
        """
            Return the android:maxSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "maxSdkVersion")

    def get_target_sdk_version(self):
        """
            Return the android:targetSdkVersion attribute

            :rtype: string
        """
        return self.get_attribute_value("uses-sdk", "targetSdkVersion")

    def get_certificate_der(self, filename):
        """
        Return the DER coded X.509 certificate from the signature file.

        :param filename: Signature filename in APK
        :returns: DER coded X.509 certificate as binary
        """
        pkcs7message = self.get_file(filename)

        pkcs7obj = cms.ContentInfo.load(pkcs7message)
        cert = pkcs7obj['content']['certificates'][0].chosen.dump()
        return cert

    def get_certificate(self, filename):
        """
        Return a X.509 certificate object by giving the name in the apk file

        :param filename: filename of the signature file in the APK
        :returns: a :class:`Certificate` certificate
        """
        cert = self.get_certificate_der(filename)
        certificate = x509.Certificate.load(cert)

        return certificate

    def get_android_resources(self):
        """
        Return the :class:`~androguard.core.bytecodes.axml.ARSCParser` object which corresponds to the resources.arsc file

        :rtype: :class:`~androguard.core.bytecodes.axml.ARSCParser`
        """
        try:
            return self.arsc["resources.arsc"]
        except KeyError:
            if "resources.arsc" not in self.zip.namelist():
                # There is a rare case, that no resource file is supplied.
                # Maybe it was added manually, thus we check here
                return None
            self.arsc["resources.arsc"] = ARSCParser(self.zip.read("resources.arsc"))
            return self.arsc["resources.arsc"]

    def is_signed_v1(self):
        """
        Returns true if a v1 / JAR signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        return self.get_signature_name() is not None

    def is_signed_v2(self):
        """
        Returns true of a v2 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v2 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v2

    def is_signed_v3(self):
        """
        Returns true of a v3 / APK signature was found.

        Returning `True` does not mean that the file is properly signed!
        It just says that there is a signature file which needs to be validated.
        """
        if self._is_signed_v3 is None:
            self.parse_v2_v3_signature()

        return self._is_signed_v3

    def read_uint32_le(self, io_stream):
        value, = unpack('<I', io_stream.read(4))
        return value

    def parse_signatures_or_digests(self, digest_bytes):
        """ Parse digests """

        if not len(digest_bytes):
            return []

        digests = []
        block = io.BytesIO(digest_bytes)

        data_len = self.read_uint32_le(block)
        while block.tell() < data_len:
            algorithm_id = self.read_uint32_le(block)
            digest_len = self.read_uint32_le(block)
            digest = block.read(digest_len)

            digests.append((algorithm_id, digest))

        return digests

    def parse_v2_v3_signature(self):
        # Need to find an v2 Block in the APK.
        # The Google Docs gives you the following rule:
        # * go to the end of the ZIP File
        # * search for the End of Central directory
        # * then jump to the beginning of the central directory
        # * Read now the magic of the signing block
        # * before the magic there is the size_of_block, so we can jump to
        # the beginning.
        # * There should be again the size_of_block
        # * Now we can read the Key-Values
        # * IDs with an unknown value should be ignored.
        f = io.BytesIO(self.__raw)

        size_central = None
        offset_central = None

        # Go to the end
        f.seek(-1, io.SEEK_END)
        # we know the minimal length for the central dir is 16+4+2
        f.seek(-20, io.SEEK_CUR)

        while f.tell() > 0:
            f.seek(-1, io.SEEK_CUR)
            r, = unpack('<4s', f.read(4))
            if r == self._PK_END_OF_CENTRAL_DIR:
                # Read central dir
                this_disk, disk_central, this_entries, total_entries, \
                size_central, offset_central = unpack('<HHHHII', f.read(16))
                # TODO according to the standard we need to check if the
                # end of central directory is the last item in the zip file
                # TODO We also need to check if the central dir is exactly
                # before the end of central dir...

                # These things should not happen for APKs
                if this_disk != 0:
                    raise BrokenAPKError("Not sure what to do with multi disk ZIP!")
                if disk_central != 0:
                    raise BrokenAPKError("Not sure what to do with multi disk ZIP!")
                break
            f.seek(-4, io.SEEK_CUR)

        if not offset_central:
            return

        f.seek(offset_central)
        r, = unpack('<4s', f.read(4))
        f.seek(-4, io.SEEK_CUR)
        if r != self._PK_CENTRAL_DIR:
            raise BrokenAPKError("No Central Dir at specified offset")

        # Go back and check if we have a magic
        end_offset = f.tell()
        f.seek(-24, io.SEEK_CUR)
        size_of_block, magic = unpack('<Q16s', f.read(24))

        self._is_signed_v2 = False
        self._is_signed_v3 = False

        if magic != self._APK_SIG_MAGIC:
            return

        # go back size_of_blocks + 8 and read size_of_block again
        f.seek(-(size_of_block + 8), io.SEEK_CUR)
        size_of_block_start, = unpack("<Q", f.read(8))
        if size_of_block_start != size_of_block:
            raise BrokenAPKError("Sizes at beginning and and does not match!")

        # Store all blocks
        while f.tell() < end_offset - 24:
            size, key = unpack('<QI', f.read(12))
            value = f.read(size - 4)
            self._v2_blocks[key] = value

        # Test if a signature is found
        if self._APK_SIG_KEY_V2_SIGNATURE in self._v2_blocks:
            self._is_signed_v2 = True

        if self._APK_SIG_KEY_V3_SIGNATURE in self._v2_blocks:
            self._is_signed_v3 = True

    def parse_v3_signing_block(self):
        """
        Parse the V2 signing block and extract all features
        """

        self._v3_signing_data = []

        # calling is_signed_v3 should also load the signature, if any
        if not self.is_signed_v3():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V3_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V3 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed) 
        #        * certificates
        #        * minSDK
        #        * maxSDK
        #        * additional attributes
        #    * minSDK
        #    * maxSDK
        #    * signatures
        #    * publickey
        size_sequence = self.read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError("size of sequence and blocksize does not match")

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = self.read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = self.read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = self.read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = self.parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = self.read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:
                len_cert = self.read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # versions
            signed_data_min_sdk = self.read_uint32_le(signed_data)
            signed_data_max_sdk = self.read_uint32_le(signed_data)

            # Addional attributes
            len_attr = self.read_uint32_le(signed_data)
            attr = signed_data.read(len_attr)

            signed_data_object = APKV3SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attr
            signed_data_object.minSDK = signed_data_min_sdk
            signed_data_object.maxSDK = signed_data_max_sdk

            # versions (should be the same as signed data's versions)
            signer_min_sdk = self.read_uint32_le(block)
            signer_max_sdk = self.read_uint32_le(block)

            # Signatures
            len_sigs = self.read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = self.parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = self.read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV3Signer()
            signer._bytes = view[off_signer:off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey
            signer.minSDK = signer_min_sdk
            signer.maxSDK = signer_max_sdk

            self._v3_signing_data.append(signer)

    def parse_v2_signing_block(self):
        """
        Parse the V2 signing block and extract all features
        """

        self._v2_signing_data = []

        # calling is_signed_v2 should also load the signature
        if not self.is_signed_v2():
            return

        block_bytes = self._v2_blocks[self._APK_SIG_KEY_V2_SIGNATURE]
        block = io.BytesIO(block_bytes)
        view = block.getvalue()

        # V2 signature Block data format:
        #
        # * signer:
        #    * signed data:
        #        * digests:
        #            * signature algorithm ID (uint32)
        #            * digest (length-prefixed) 
        #        * certificates
        #        * additional attributes
        #    * signatures
        #    * publickey

        size_sequence = self.read_uint32_le(block)
        if size_sequence + 4 != len(block_bytes):
            raise BrokenAPKError("size of sequence and blocksize does not match")

        while block.tell() < len(block_bytes):
            off_signer = block.tell()
            size_signer = self.read_uint32_le(block)

            # read whole signed data, since we might to parse
            # content within the signed data, and mess up offset
            len_signed_data = self.read_uint32_le(block)
            signed_data_bytes = block.read(len_signed_data)
            signed_data = io.BytesIO(signed_data_bytes)

            # Digests
            len_digests = self.read_uint32_le(signed_data)
            raw_digests = signed_data.read(len_digests)
            digests = self.parse_signatures_or_digests(raw_digests)

            # Certs
            certs = []
            len_certs = self.read_uint32_le(signed_data)
            start_certs = signed_data.tell()
            while signed_data.tell() < start_certs + len_certs:
                len_cert = self.read_uint32_le(signed_data)
                cert = signed_data.read(len_cert)
                certs.append(cert)

            # Additional attributes
            len_attr = self.read_uint32_le(signed_data)
            attributes = signed_data.read(len_attr)

            signed_data_object = APKV2SignedData()
            signed_data_object._bytes = signed_data_bytes
            signed_data_object.digests = digests
            signed_data_object.certificates = certs
            signed_data_object.additional_attributes = attributes

            # Signatures
            len_sigs = self.read_uint32_le(block)
            raw_sigs = block.read(len_sigs)
            sigs = self.parse_signatures_or_digests(raw_sigs)

            # PublicKey
            len_publickey = self.read_uint32_le(block)
            publickey = block.read(len_publickey)

            signer = APKV2Signer()
            signer._bytes = view[off_signer:off_signer + size_signer]
            signer.signed_data = signed_data_object
            signer.signatures = sigs
            signer.public_key = publickey

            self._v2_signing_data.append(signer)

    def get_certificates_der_v2(self):
        """
        Return a list of DER coded X.509 certificates from the v3 signature block
        """

        if self._v2_signing_data == None:
            self.parse_v2_signing_block()

        certs = []
        for signed_data in [signer.signed_data for signer in self._v2_signing_data]:
            for cert in signed_data.certificates:
                certs.append(cert)

        return certs

    def get_certificates_v2(self):
        """
        Return a list of :class:`asn1crypto.x509.Certificate` which are found
        in the v2 signing block.
        Note that we simply extract all certificates regardless of the signer.
        Therefore this is just a list of all certificates found in all signers.
        """
        return [x509.Certificate.load(cert) for cert in self.get_certificates_der_v2()]

    def get_signature_name(self):
        """
            Return the name of the first signature file found.
        """
        if self.get_signature_names():
            return self.get_signature_names()[0]
        else:
            # Unsigned APK
            return None

    def get_signature_names(self):
        """
        Return a list of the signature file names (v1 Signature / JAR
        Signature)

        :rtype: List of filenames matching a Signature
        """
        signature_expr = re.compile(r"^(META-INF/)(.*)(\.RSA|\.EC|\.DSA)$")
        signatures = []

        for i in self.get_files():
            if signature_expr.search(i):
                if "{}.SF".format(i.rsplit(".", 1)[0]) in self.get_files():
                    signatures.append(i)
                else:
                    log.warning("v1 signature file {} missing .SF file - Partial signature!".format(i))

        return signatures

    def show(self):
        self.get_files_types()

        print("FILES: ")
        for i in self.get_files():
            try:
                print("\t", i, self._files[i], "%x" % self.files_crc32[i])
            except KeyError:
                print("\t", i, "%x" % self.files_crc32[i])

        print("DECLARED PERMISSIONS:")
        declared_permissions = self.get_declared_permissions()
        for i in declared_permissions:
            print("\t", i)

        print("REQUESTED PERMISSIONS:")
        requested_permissions = self.get_permissions()
        for i in requested_permissions:
            print("\t", i)

        print("MAIN ACTIVITY: ", self.get_main_activity())

        print("ACTIVITIES: ")
        activities = self.get_activities()
        for i in activities:
            filters = self.get_intent_filters("activity", i)
            print("\t", i, filters or "")

        print("SERVICES: ")
        services = self.get_services()
        for i in services:
            filters = self.get_intent_filters("service", i)
            print("\t", i, filters or "")

        print("RECEIVERS: ")
        receivers = self.get_receivers()
        for i in receivers:
            filters = self.get_intent_filters("receiver", i)
            print("\t", i, filters or "")

        print("PROVIDERS: ", self.get_providers())

        if self.is_signed_v1():
            print("CERTIFICATES v1:")
            for c in self.get_signature_names():
                show_Certificate(self.get_certificate(c))

        if self.is_signed_v2():
            print("CERTIFICATES v2:")
            for c in self.get_certificates_v2():
                show_Certificate(c)


def show_Certificate(cert, short=False):
    """
        Print Fingerprints, Issuer and Subject of an X509 Certificate.

        :param cert: X509 Certificate to print
        :param short: Print in shortform for DN (Default: False)

        :type cert: :class:`asn1crypto.x509.Certificate`
        :type short: Boolean
    """
    print("SHA1 Fingerprint: {}".format(cert.sha1_fingerprint))
    print("SHA256 Fingerprint: {}".format(cert.sha256_fingerprint))
    print("Issuer: {}".format(get_certificate_name_string(cert.issuer.native, short=short)))
    print("Subject: {}".format(get_certificate_name_string(cert.subject.native, short=short)))
