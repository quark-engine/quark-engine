# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import unittest
import zipfile
from os import PathLike
from pathlib import Path

import pytest
from quark.core.axmlreader import AxmlReader, ResValue
from quark.core.axmlreader.python import PythonImp


def extractManifest(samplePath: PathLike) -> str:
    folder = Path(samplePath).parent

    with zipfile.ZipFile(samplePath) as apk:
        apk.extract("AndroidManifest.xml", path=folder)

    return str(folder / "AndroidManifest.xml")


@pytest.fixture(scope="session",
                params=(
                    AxmlReader,
                    PythonImp
                ),
                ids=("Rz/R2-based Implementation",
                     "Python-based Implementation"))
def AxmlReaderImp(request):
    axmlReaderImp = request.param
    yield axmlReaderImp


@pytest.fixture(scope="session")
def MANIFEST_PATH_14d9f(SAMPLE_PATH_14d9f):
    return extractManifest(SAMPLE_PATH_14d9f)


@pytest.fixture(scope="session")
def MANIFEST_PATH_pivaa(SAMPLE_PATH_pivaa):
    return extractManifest(SAMPLE_PATH_pivaa)


class TestAxmlReader:
    @staticmethod
    def testIter(AxmlReaderImp, MANIFEST_PATH_14d9f) -> None:
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            expectedTag = {
                "Address": 3728,
                "Type": 256,
                "Prefix": 9,
                "Uri": 10,
            }

            tag = next(iter(axmlReader))

            helper = unittest.TestCase()
            helper.assertDictEqual(tag, expectedTag)

    @staticmethod
    def testClose(MANIFEST_PATH_14d9f):
        with PythonImp(MANIFEST_PATH_14d9f) as axmlReader:
            assert axmlReader._file.closed is False
        assert axmlReader._file.closed is True

    @staticmethod
    def testFileSize(AxmlReaderImp, MANIFEST_PATH_14d9f):
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            assert axmlReader.file_size == 7676

    @staticmethod
    def testAxmlSize(AxmlReaderImp, MANIFEST_PATH_14d9f):
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            assert axmlReader.axml_size == 7676

    @staticmethod
    def testGetStringFromUtf16Apk(AxmlReaderImp, MANIFEST_PATH_14d9f):
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            assert axmlReader.get_string(13) == "manifest"

    @staticmethod
    def testGetStringFromUtf8Apk(AxmlReaderImp, MANIFEST_PATH_pivaa):
        with AxmlReaderImp(MANIFEST_PATH_pivaa) as axmlReader:
            assert axmlReader.get_string(58) == "manifest"

    @staticmethod
    def testGetAttributes(AxmlReaderImp, MANIFEST_PATH_14d9f):
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            manifestTag = list(axmlReader)[1]

            expectedAttributes = [
                ResValue(namespace=10, name=0, value=-1, type=16, data=1),
                ResValue(namespace=10, name=1, value=15, type=3, data=15),
                ResValue(namespace=-1, name=12, value=14, type=3, data=14),
            ]

            attributes = axmlReader.get_attributes(manifestTag)

            for expectedAttrib, attrib in zip(expectedAttributes, attributes):
                assert expectedAttrib == attrib

    @staticmethod
    def testGetXmlTree(AxmlReaderImp, MANIFEST_PATH_14d9f):
        with AxmlReaderImp(MANIFEST_PATH_14d9f) as axmlReader:
            xml = axmlReader.get_xml_tree()
            manifestLabel = xml.getroot()
            assert len(manifestLabel.findall("uses-sdk")) == 1
            assert len(manifestLabel.findall("application")) == 1
            assert len(manifestLabel.findall("uses-permission")) == 29
