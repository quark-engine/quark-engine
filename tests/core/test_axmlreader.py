# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import unittest
import zipfile
from os import PathLike
from pathlib import Path

import pytest
from quark.core.axmlreader import AxmlReader


def extractManifest(samplePath: PathLike) -> str:
    folder = Path(samplePath).parent

    with zipfile.ZipFile(samplePath) as apk:
        apk.extract("AndroidManifest.xml", path=folder)

    return str(folder / "AndroidManifest.xml")


@pytest.fixture(scope="session")
def MANIFEST_PATH_14d9f(SAMPLE_PATH_14d9f):
    return extractManifest(SAMPLE_PATH_14d9f)


class TestAxmlReader:
    @staticmethod
    def testIter(MANIFEST_PATH_14d9f) -> None:
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        expectedTag = {"Address": 3728, "Type": 256, "Prefix": 9, "Uri": 10}

        tag = next(iter(axmlReader))

        helper = unittest.TestCase()
        helper.assertDictEqual(tag, expectedTag)

    @staticmethod
    def testFileSize(MANIFEST_PATH_14d9f):
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        assert axmlReader.file_size == 7676

    @staticmethod
    def testAxmlSize(MANIFEST_PATH_14d9f):
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        assert axmlReader.axml_size == 7676

    @staticmethod
    def testGetString(MANIFEST_PATH_14d9f):
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        assert axmlReader.get_string(13) == "manifest"

    @staticmethod
    def testGetAttributes(MANIFEST_PATH_14d9f):
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        manifestTag = list(axmlReader)[1]

        expectedAttributes = [
            {"Namespace": 10, "Name": 0, "Value": -1, "Type": 16, "Data": 1},
            {"Namespace": 10, "Name": 1, "Value": 15, "Type": 3, "Data": 15},
            {"Namespace": -1, "Name": 12, "Value": 14, "Type": 3, "Data": 14},
        ]

        attributes = axmlReader.get_attributes(manifestTag)

        helper = unittest.TestCase()
        for expectedAttrib, attrib in zip(expectedAttributes, attributes):
            helper.assertDictEqual(expectedAttrib, attrib)

    @staticmethod
    def testGetXmlTree(MANIFEST_PATH_14d9f):
        axmlReader = AxmlReader(MANIFEST_PATH_14d9f)
        xml = axmlReader.get_xml_tree()
        manifestLabel = xml.getroot()
        assert len(manifestLabel.findall("uses-sdk")) == 1
        assert len(manifestLabel.findall("application")) == 1
        assert len(manifestLabel.findall("uses-permission")) == 29
