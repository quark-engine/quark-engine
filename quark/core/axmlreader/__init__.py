import enum
import functools
import os.path
import pkg_resources

import rzpipe

# Resource Types Definition
# Please reference to
# https://android.googlesource.com/platform/frameworks/base/+/master/libs/androidfw/include/androidfw/ResourceTypes.h

# ResChunk_header types
RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_TABLE_TYPE = 0x0002
RES_XML_TYPE = 0x0003

# Chunk types in RES_XML_TYPE
RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_LAST_CHUNK_TYPE = 0x017F
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# Chunk types in RES_TABLE_TYPE
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC_TYPE = 0x0202
RES_TABLE_LIBRARY_TYPE = 0x0203
RES_TABLE_OVERLAYABLE_TYPE = 0x0204
RES_TABLE_OVERLAYABLE_POLICY_TYPE = 0x0205


class Res_value_type(enum.Enum):
    TYPE_NULL = (0x00,)
    TYPE_REFERENCE = (0x01,)
    TYPE_ATTRIBUTE = (0x02,)
    TYPE_STRING = (0x03,)
    TYPE_FLOAT = (0x04,)
    TYPE_DIMENSION = (0x05,)
    TYPE_FRACTION = (0x06,)
    TYPE_DYNAMIC_REFERENCE = (0x07,)
    TYPE_DYNAMIC_ATTRIBUTE = (0x08,)
    TYPE_FIRST_INT = (0x10,)
    TYPE_INT_DEC = (0x10,)
    TYPE_INT_HEX = (0x11,)
    TYPE_INT_BOOLEAN = (0x12,)
    TYPE_FIRST_COLOR_INT = (0x1C,)
    TYPE_INT_COLOR_ARGB8 = (0x1C,)
    TYPE_INT_COLOR_RGB8 = (0x1D,)
    TYPE_INT_COLOR_ARGB4 = (0x1E,)
    TYPE_INT_COLOR_RGB4 = (0x1F,)
    TYPE_LAST_COLOR_INT = (0x1F,)
    TYPE_LAST_INT = 0x1F


class AxmlException(Exception):
    """
    A Exception for AxmlReader
    """

    def __init__(self, message):
        super(AxmlException, self).__init__(message)


class AxmlReader(object):
    """
    A Class that parses the Android XML file
    """

    def __init__(self, file_path, structure_path=None):
        if structure_path is None:
            structure_path = pkg_resources.resource_filename(
                "quark.core.axmlreader", "axml_definition"
            )

        if not os.path.isfile(structure_path):
            raise AxmlException(
                f"Cannot find printing format definition file"
                f" of Rizin in {structure_path}"
            )

        self._rz = rzpipe.open(file_path)
        self._rz.cmd(f"pfo {structure_path}")

        self._file_size = int(self._rz.cmd("i~size[1]"), 16)
        self._ptr = 0

        self._cache = {}

        if self._file_size > 0xFFFF_FFFF:
            raise AxmlException("Filesize exceeds theoretical upper bound.")
        elif self._file_size < 8:
            raise AxmlException("Filesize exceeds theoretical lower bound.")

        # File Header
        header = self._rz.cmdj("pfj axml_ResChunk_header @ 0x0")

        self._data_type = header[0]["value"]
        self._axml_size = header[2]["value"]
        header_size = header[1]["value"]

        if self._data_type != RES_XML_TYPE or header_size != 0x8:
            raise AxmlException(
                f"Error parsing first header(type: {self._data_type},"
                f" size: {header_size})."
            )

        if self._axml_size > self._file_size:
            raise AxmlException(
                f"Decleared size ({self._axml_size} bytes) is"
                f" larger than total size({self._file_size})."
            )

        self._ptr += 8
        if self._ptr >= self._axml_size:
            return

        # String Pool
        string_pool_header = self._rz.cmdj("pfj axml_ResStringPool_header @ 8")

        string_pool_size = string_pool_header[0]["value"][2]["value"]

        if string_pool_size > self._axml_size - self._ptr:
            raise AxmlException(
                f"Error parsing string pool, there should"
                f" be {string_pool_size}"
                f" bytes but only {self._axml_size - self._ptr} bytes."
            )

        header = string_pool_header[0]["value"]
        header_type = header[0]["value"]
        header_size = header[1]["value"]

        if header_type != RES_STRING_POOL_TYPE:
            raise AxmlException(
                f"Error parsing string pool, expect string pool"
                f" data at {self._ptr} bytes."
            )

        if header_size != 28:
            raise AxmlException(
                f"Error parsing string pool, heardsize should "
                f"be 16 bytes rather than { header_size } bytes."
            )

        self._stringCount = string_pool_header[1]["value"]
        stringStart = string_pool_header[4]["value"]

        self._rz.cmd(f"f string_pool_header @ 0x8 ")
        string_pool_index = header_size + self._ptr
        self._rz.cmd(f"f string_pool_index @ { string_pool_index }")
        string_pool_data = stringStart + self._ptr
        self._rz.cmd(f"f string_pool_data @ { string_pool_data }")

        self._ptr += string_pool_size
        if self._ptr >= self._axml_size:
            return

        # Resource Map (Optional)
        header = self._rz.cmdj(f"pfj axml_ResChunk_header @ {self._ptr}")

        header_type = header[0]["value"]
        if header_type == RES_XML_RESOURCE_MAP_TYPE:
            map_size = header[2]["value"]

            # Skip all the resource map

            if map_size > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Map size should be {map_size} bytes rather"
                    f" than {self._axml_size - self._ptr} bytes."
                )

            self._ptr += map_size
            if self._ptr >= self._axml_size:
                return

    def __iter__(self):
        while self._axml_size - self._ptr >= 16:
            header = self._rz.cmdj(f"pfj axml_ResXMLTree_node @ {self._ptr}")

            node_type = header[0]["value"][0]["value"]
            header_size = header[0]["value"][1]["value"]
            node_size = header[0]["value"][2]["value"]

            if header_size != 16:
                raise AxmlException(
                    f"heardsize should be 16 bytes rather"
                    f" than { header_size } bytes."
                )

            if node_size > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Not enough data left, need {node_size} bytes"
                    f" but {self._axml_size - self._ptr} bytes left."
                )

            ext_ptr = self._ptr + 16

            node = {"Address": self._ptr, "Type": node_type}

            if node_type == RES_XML_START_ELEMENT_TYPE:
                ext = self._rz.cmdj(f"pfj axml_ResXMLTree_attrExt @ { ext_ptr }")

                node["Namespace"] = ext[0]["value"][0]["value"]
                node["Name"] = ext[1]["value"][0]["value"]

                # Attributes
                # node['AttrCount'] = ext[4]['value']

            elif node_type == RES_XML_END_ELEMENT_TYPE:
                ext = self._rz.cmdj(f"pfj axml_ResXMLTree_endElementExt @ { ext_ptr }")

                node["Namespace"] = ext[0]["value"][0]["value"]
                node["Name"] = ext[1]["value"][0]["value"]

            elif node_type in [
                RES_XML_START_NAMESPACE_TYPE,
                RES_XML_END_NAMESPACE_TYPE,
            ]:
                ext = self._rz.cmdj(f"pfj axml_ResXMLTree_namespaceExt @ { ext_ptr }")

                node["Prefix"] = ext[0]["value"][0]["value"]
                node["Uri"] = ext[1]["value"][0]["value"]

            elif node_type == RES_XML_CDATA_TYPE:
                ext = self._rz.cmdj(f"pfj axml_ResXMLTree_cdataExt @ { ext_ptr }")

                node["Data"] = ext[0]["value"][0]["value"]
                # typedData

            else:
                self._ptr = self._ptr + node_size
                continue

            self._ptr = self._ptr + node_size
            yield node

    @property
    def file_size(self):
        return self._file_size

    @property
    def axml_size(self):
        return self._axml_size

    @functools.lru_cache()
    def get_string(self, index):
        if index < 0 or index >= self._stringCount:
            return None

        return self._rz.cmdj(
            f"pfj Z @ string_pool_data + `pfv n4 "
            f"@ string_pool_index+ {index}*4` + 2"
        )[0]["string"]

    def get_attributes(self, node):
        if node["Type"] != RES_XML_START_ELEMENT_TYPE:
            return None
        extAddress = int(node["Address"]) + 16

        attrExt = self._rz.cmdj(f"pfj axml_ResXMLTree_attrExt @ {extAddress}")

        attrAddress = extAddress + attrExt[2]["value"]
        attributeSize = attrExt[3]["value"]
        attributeCount = attrExt[4]["value"]
        result = []
        for _ in range(attributeCount):
            attr = self._rz.cmdj(f"pfj axml_ResXMLTree_attribute @ {attrAddress}")

            result.append(
                {
                    "Namespace": attr[0]["value"][0]["value"],
                    "Name": attr[1]["value"][0]["value"],
                    "Value": attr[2]["value"][0]["value"],
                    "Type": attr[3]["value"][2]["value"],
                    "Data": attr[3]["value"][3]["value"],
                }
            )

            attrAddress = attrAddress + attributeSize

        return result

    def __del__(self):
        try:
            self._rz.quit()
        except BaseException:
            pass
