# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import functools
import os.path
from typing import Any
from collections.abc import Iterator
from xml.etree.ElementTree import Element as XMLElement  # nosec B405
import struct

from quark.core.axmlreader import (
    RES_STRING_POOL_TYPE,
    RES_XML_CDATA_TYPE,
    RES_XML_END_ELEMENT_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    RES_XML_TYPE,
    AxmlException,
    AxmlReader,
    Res_value_type,
    ResChunkHeader,
    ResValue
)


class PythonImp(AxmlReader):
    """
    A Class that parses the Android XML file using the builtin library `struct`
    """

    def __init__(self, filePath):
        self._file_size = os.path.getsize(filePath)
        if self._file_size > 0xFFFF_FFFF:
            raise AxmlException("Filesize exceeds theoretical upper bound.")
        elif self._file_size < 8:
            raise AxmlException("Filesize exceeds theoretical lower bound.")

        self._file = open(filePath, "rb")

        self._ptr = 0
        self._cache = {}

        # File Header
        ResChunkHeaderFormat = "h h i"
        fileHeader = self.__readStructWithFormat(
            ResChunkHeaderFormat, self._ptr
        )

        self._data_type = fileHeader[0]
        self._axml_size = fileHeader[2]
        headerSize = fileHeader[1]

        if self._data_type != RES_XML_TYPE or headerSize != 0x8:
            raise AxmlException(
                f"Error parsing first header(type: {self._data_type},"
                f" size: {headerSize})."
            )

        if self._axml_size > self._file_size:
            raise AxmlException(
                f"Declared size ({self._axml_size} bytes) is"
                f" larger than total size({self._file_size})."
            )

        self._ptr += 8
        if self._ptr >= self._axml_size:
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

        if stringPoolSize > self._axml_size - self._ptr:
            raise AxmlException(
                f"Error parsing string pool, there should"
                f" be {stringPoolSize}"
                f" bytes but only {self._axml_size - self._ptr} bytes."
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
        if self._ptr >= self._axml_size:
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

            if mapSize > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Map size should be {mapSize} bytes rather"
                    f" than {self._axml_size - self._ptr} bytes."
                )

            self._ptr += mapSize
            if self._ptr >= self._axml_size:
                return

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __iter__(self) -> Iterator[ResChunkHeader]:
        """
        Inherited from AxmlReader.
        Get an iterator that walks through the content of the Android XML
          binary.

        :raises AxmlException: if the given file is not a valid Android XML
         binary
        :yield: header of a resource chunk defined in the binary
        """
        while self._axml_size - self._ptr >= 16:
            ResXMLTreeNodeFormat = "h h i i i"
            header = self.__readStructWithFormat(
                ResXMLTreeNodeFormat, self._ptr
            )

            nodeType = header[0]
            headerSize = header[1]
            nodeSize = header[2]

            if headerSize != 16:
                raise AxmlException(
                    f"Header size should be 16 bytes rather"
                    f" than { headerSize } bytes."
                )

            if nodeSize > self._axml_size - self._ptr:
                raise AxmlException(
                    f"Not enough data left, need {nodeSize} bytes"
                    f" but {self._axml_size - self._ptr} bytes left."
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

    def __readStructWithFormat(
        self,
        structFormat: str,
        position: int
    ) -> list[Any] | None:
        structSize = struct.calcsize(structFormat)
        self._file.seek(position)
        data = self._file.read(structSize)
        if data:
            return list(struct.unpack(structFormat, data))
        return None

    def close(self):
        if self._file and not self._file.closed:
            self._file.close()

    def __readAsStringUntilNull(self, position, encodingMethod) -> str | None:

        if encodingMethod == "utf-16":
            numBytesReadPerLoop = 2
            dataFormat = "<h"
        elif encodingMethod == "utf-8":
            numBytesReadPerLoop = 1
            dataFormat = "b"
        else:
            return None

        self._file.seek(position)
        result = []
        while True:
            byteData = self._file.read(numBytesReadPerLoop)

            if len(byteData) < numBytesReadPerLoop:
                break

            charCode = struct.unpack(dataFormat, byteData)[0]

            if charCode == 0:
                break

            result.append(chr(charCode))

        return "".join(result)

    @functools.lru_cache
    def get_string(self, index) -> str | None:
        """
        Inherited from AxmlReader.
        Get the specified string from the string pool.

        :param index: the index of the string in the string pool.
        :return: the string at the specified index, None otherwise.
        """
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

    def get_attributes(self, chunk: ResChunkHeader) -> list[ResValue] | None:
        """
        Inherited from AxmlReader.
        Get the attributes of a resource chunk

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
        name = self.get_string(chunk["Name"])

        attributes = {}
        for rawAttribute in self.get_attributes(chunk):
            attrNamespace = self.get_string(rawAttribute.namespace)
            attrName = self.get_string(rawAttribute.name)

            dataType = rawAttribute.type
            rawData = rawAttribute.data
            if dataType == Res_value_type.TYPE_STRING.value:
                value = self.get_string(rawData)
            elif dataType == Res_value_type.TYPE_INT_BOOLEAN.value:
                value = bool(abs(rawData))
            else:
                value = rawAttribute.data

            if attrNamespace:
                attrName = "{" + attrNamespace + "}" + attrName

            attributes[attrName] = value

        return XMLElement(name, attributes)

    def _find_manifest(
        self, chunkIterator: Iterator[ResChunkHeader]
    ) -> XMLElement:
        """
        Inherited from AxmlReader.
        Find the resource chunk of the first XML label named manifest and
         convert it into an XMLElement instance.

        :param chunkIterator: iterator of the resource chunk headers
        :return: XMLElement instance
        """
        manifestChunk = next(
            (
                chunk
                for chunk in chunkIterator
                if chunk["Type"] == RES_XML_START_ELEMENT_TYPE
                and self.get_string(chunk["Name"]) == "manifest"
            ),
            None,
        )

        if manifestChunk:
            return self.__convertTagToXmlElement(manifestChunk)

    def __del__(self):
        try:
            self.close()
        except Exception as e:
            raise e
