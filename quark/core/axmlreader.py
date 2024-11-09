import enum
import functools
import os.path
from collections import namedtuple
from typing import Any, Dict, Iterator, List, Tuple
from xml.etree.ElementTree import Element as XMLElement  # nosec B405
from xml.etree.ElementTree import ElementTree as XMLElementTree  # nosec B405
import struct

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

ResChunkHeader = Dict[str, Any]
ResValue = namedtuple(
    "ResValue", ["namespace", "name", "type", "value", "data"]
)


class ResValueType(enum.Enum):
    """
    List all possible types of a value in the Android XML binary.
    """

    TYPE_NULL = 0x00
    TYPE_REFERENCE = 0x01
    TYPE_ATTRIBUTE = 0x02
    TYPE_STRING = 0x03
    TYPE_FLOAT = 0x04
    TYPE_DIMENSION = 0x05
    TYPE_FRACTION = 0x06
    TYPE_DYNAMIC_REFERENCE = 0x07
    TYPE_DYNAMIC_ATTRIBUTE = 0x08
    TYPE_FIRST_INT = 0x10
    TYPE_INT_DEC = 0x10
    TYPE_INT_HEX = 0x11
    TYPE_INT_BOOLEAN = 0x12
    TYPE_FIRST_COLOR_INT = 0x1C
    TYPE_INT_COLOR_ARGB8 = 0x1C
    TYPE_INT_COLOR_RGB8 = 0x1D
    TYPE_INT_COLOR_ARGB4 = 0x1E
    TYPE_INT_COLOR_RGB4 = 0x1F
    TYPE_LAST_COLOR_INT = 0x1F
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

    def __init__(self, filePath):

        self._fileSize = os.path.getsize(filePath)
        if self._fileSize > 0xFFFF_FFFF:
            raise AxmlException("Filesize exceeds theoretical upper bound.")
        elif self._fileSize < 8:
            raise AxmlException("Filesize exceeds theoretical lower bound.")

        self._file = open(filePath, "rb")

        self._ptr = 0
        self._cache = {}

        # File Header
        ResChunkHeaderFormat = "h h i"
        fileHeader = self.__readStructWithFormat(
            ResChunkHeaderFormat, self._ptr
        )

        self._dataType = fileHeader[0]
        self._axmlSize = fileHeader[2]
        headerSize = fileHeader[1]

        if self._dataType != RES_XML_TYPE or headerSize != 0x8:
            raise AxmlException(
                f"Error parsing first header(type: {self._dataType},"
                f" size: {headerSize})."
            )

        if self._axmlSize > self._fileSize:
            raise AxmlException(
                f"Decleared size ({self._axmlSize} bytes) is"
                f" larger than total size({self._fileSize})."
            )

        self._ptr += 8
        if self._ptr >= self._axmlSize:
            return

        # String Pool

        stringPoolHeaderPosition = self._ptr
        ResStringPoolHeaderFormat = "h h i i i i i i"
        stringPoolHeader = self.__readStructWithFormat(
            ResStringPoolHeaderFormat, self._ptr
        )

        headerType = stringPoolHeader[0]
        headerSize = stringPoolHeader[1]
        stringPoolSize = stringPoolHeader[2]

        if stringPoolSize > self._axmlSize - self._ptr:
            raise AxmlException(
                f"Error parsing string pool, there should"
                f" be {stringPoolSize}"
                f" bytes but only {self._axmlSize - self._ptr} bytes."
            )

        if headerType != RES_STRING_POOL_TYPE:
            raise AxmlException(
                f"Error parsing string pool, expect string pool"
                f" data at {self._ptr} bytes."
            )

        if headerSize != 28:
            raise AxmlException(
                f"Error parsing string pool, headerSize should "
                f"be 16 bytes rather than { headerSize } bytes."
            )

        self._ptr += stringPoolSize
        if self._ptr >= self._axmlSize:
            return

        self._stringCount = stringPoolHeader[3]
        self._isUtf8Used = (stringPoolHeader[5] & (1 << 8)) != 0
        stringStart = stringPoolHeader[6]

        self._stringPoolIndexPosition = stringPoolHeaderPosition + headerSize
        self._stringPoolDataPosition = stringPoolHeaderPosition + stringStart

        # Resource Map (Optional)
        resourceMapHeader = self.__readStructWithFormat(
            ResChunkHeaderFormat, self._ptr
        )

        headerType = resourceMapHeader[0]
        if headerType == RES_XML_RESOURCE_MAP_TYPE:
            mapSize = resourceMapHeader[2]

            # Skip all the resource map

            if mapSize > self._axmlSize - self._ptr:
                raise AxmlException(
                    f"Map size should be {mapSize} bytes rather"
                    f" than {self._axmlSize - self._ptr} bytes."
                )

            self._ptr += mapSize
            if self._ptr >= self._axmlSize:
                return

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __iter__(self) -> Iterator[ResChunkHeader]:
        """Get an iterator that walks through the content of the Android XML
         binary.

        :raises AxmlException: if the given file is not a valid Android XML
         binary
        :yield: header of a resource chunk defined in the binary
        """
        while self._axmlSize - self._ptr >= 16:
            ResXMLTreeNodeFormat = "h h i i i"
            header = self.__readStructWithFormat(
                ResXMLTreeNodeFormat, self._ptr
            )

            nodeType = header[0]
            headerSize = header[1]
            nodeSize = header[2]

            if headerSize != 16:
                raise AxmlException(
                    f"heardsize should be 16 bytes rather"
                    f" than { headerSize } bytes."
                )

            if nodeSize > self._axmlSize - self._ptr:
                raise AxmlException(
                    f"Not enough data left, need {nodeSize} bytes"
                    f" but {self._axmlSize - self._ptr} bytes left."
                )

            extPtr = self._ptr + 16

            chunk = {"Address": self._ptr, "Type": nodeType}

            if nodeType == RES_XML_START_ELEMENT_TYPE:
                ResXMLTreeAttrExtFormat = "i i h h h h h h"
                ext = self.__readStructWithFormat(
                    ResXMLTreeAttrExtFormat, extPtr
                )

                chunk["Namespace"] = ext[0]
                chunk["Name"] = ext[1]

            elif nodeType == RES_XML_END_ELEMENT_TYPE:
                ResXMLTreeEndElementExtFormat = "i i"
                ext = self.__readStructWithFormat(
                    ResXMLTreeEndElementExtFormat, extPtr
                )

                chunk["Namespace"] = ext[0]
                chunk["Name"] = ext[1]

            elif nodeType in [
                RES_XML_START_NAMESPACE_TYPE,
                RES_XML_END_NAMESPACE_TYPE,
            ]:
                ResXMLTreeNamespaceExtFormat = "i i"
                ext = self.__readStructWithFormat(
                    ResXMLTreeNamespaceExtFormat, extPtr
                )

                chunk["Prefix"] = ext[0]
                chunk["Uri"] = ext[1]

            elif nodeType == RES_XML_CDATA_TYPE:
                ResXMLTreeCdataExtFormat = "i h b b i"
                ext = self.__readStructWithFormat(
                    ResXMLTreeCdataExtFormat, extPtr
                )

                chunk["Data"] = ext[0]

            else:
                self._ptr = self._ptr + nodeSize
                continue

            self._ptr = self._ptr + nodeSize
            yield chunk

    def __readStructWithFormat(self, format: str, position: int) -> Tuple[Any]:
        structSize = struct.calcsize(format)
        self._file.seek(position)
        data = self._file.read(structSize)
        if data:
            return struct.unpack(format, data)
        return None

    @property
    def fileSize(self):
        return self._fileSize

    @property
    def axmlSize(self):
        return self._axmlSize

    def close(self):
        if self._file and not self._file.closed:
            self._file.close()

    def __readAsStringUntilNull(self, position, encodingMethod) -> str:

        if encodingMethod == "utf-16":
            numBytesReadPerLoop = 2
            dataFormat = "<h"
        elif encodingMethod == "utf-8":
            numBytesReadPerLoop = 1
            dataFormat = "b"
        else:
            return

        self._file.seek(position)
        result = []
        while True:
            bytes = self._file.read(numBytesReadPerLoop)

            if len(bytes) < numBytesReadPerLoop:
                break

            charCode = struct.unpack(dataFormat, bytes)[0]

            if charCode == 0:
                break

            result.append(chr(charCode))

        return "".join(result)

    @functools.lru_cache()
    def getString(self, index):
        if index < 0 or index >= self._stringCount:
            return None
        if self._isUtf8Used:
            encodingMethod = "utf-8"
        else:
            encodingMethod = "utf-16"

        stringPoolIndex = self.__readStructWithFormat(
            "i", self._stringPoolIndexPosition + index * 4
        )[0]

        return self.__readAsStringUntilNull(
            self._stringPoolDataPosition + stringPoolIndex + 2, encodingMethod
        )

    def getAttributes(self, chunk: ResChunkHeader) -> List[ResValue]:
        """Get the attributes of a resource chunk

        :param chunk: header of a resource chunk
        :return: python list that holds attributes
        """
        if chunk["Type"] != RES_XML_START_ELEMENT_TYPE:
            return None
        extAddress = int(chunk["Address"]) + 16

        ResXMLTreeAttrExtFormat = "i i h h h h h h"
        attrExt = self.__readStructWithFormat(
            ResXMLTreeAttrExtFormat, extAddress
        )

        attrAddress = extAddress + attrExt[2]
        attributeSize = attrExt[3]
        attributeCount = attrExt[4]
        attributes = []
        for _ in range(attributeCount):
            ResXMLTreeAttrFormat = "i i i h b b i"
            attr = self.__readStructWithFormat(
                ResXMLTreeAttrFormat, attrAddress
            )

            value = ResValue(
                namespace=attr[0],
                name=attr[1],
                value=attr[2],
                type=attr[5],
                data=attr[6],
            )
            attributes.append(value)

            attrAddress = attrAddress + attributeSize

        return attributes

    def __convertTagToXmlElement(self, chunk: ResChunkHeader) -> XMLElement:
        """Convert a resource chunk in the Android XML binary into an
         XMLElement instance.

        :param chunk: header of a resource chunk in the Android XML binary
        :return: XMLElement instance
        """
        name = self.getString(chunk["Name"])

        attributes = {}
        for rawAttribute in self.getAttributes(chunk):
            attrNamespace = self.getString(rawAttribute.namespace)
            attrName = self.getString(rawAttribute.name)

            dataType = rawAttribute.type
            rawData = rawAttribute.data
            if dataType == ResValueType.TYPE_STRING.value:
                value = self.getString(rawData)
            elif dataType == ResValueType.TYPE_INT_BOOLEAN.value:
                value = bool(abs(rawData))
            else:
                value = rawAttribute.data

            if attrNamespace:
                attrName = "{" + attrNamespace + "}" + attrName

            attributes[attrName] = value

        return XMLElement(name, attributes)

    def __findManifest(
        self, chunkIterator: Iterator[ResChunkHeader]
    ) -> XMLElement:
        """Find the resource chunk of the first XML label named manifest and
         convert it into an XMLElement instance.

        :param chunk_iterator: iterator of the resource chunk headers
        :return: XMLElement instance
        """
        manifestChunk = next(
            (
                chunk
                for chunk in chunkIterator
                if chunk["Type"] == RES_XML_START_ELEMENT_TYPE
                and self.getString(chunk["Name"]) == "manifest"
            ),
            None,
        )

        if manifestChunk:
            return self.__convertTagToXmlElement(manifestChunk)

    def getXmlTree(self) -> XMLElementTree:
        """
        Return the parsed XML corresponding to the AndroidManifest.xml file.

        :return: the content of the file
        """
        fileIterator = iter(self)
        root = self.__findManifest(fileIterator)

        stack = [root]
        for tag in fileIterator:
            tagType = tag["Type"]

            if tagType == RES_XML_END_ELEMENT_TYPE:
                stack.pop()

            elif tagType == RES_XML_START_ELEMENT_TYPE:
                element = self.__convertTagToXmlElement(tag)

                parent = stack[-1]
                parent.append(element)

                stack.append(element)

        return XMLElementTree(root)

    def __del__(self):
        try:
            self.close()
        except BaseException:
            pass
