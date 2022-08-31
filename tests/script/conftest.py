# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
import pytest
import requests


SAMPLE_SOURCE_URL = (
    "https://github.com/quark-engine/apk-malware-samples"
    "/raw/master/14d9f1a92dd984d6040cc41ed06e273e.apk"
)
SAMPLE_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"


@pytest.fixture(scope="session")
def SAMPLE_PATH(tmp_path_factory: pytest.TempPathFactory) -> str:
    folder = os.path.splitext(os.path.basename(__file__))[0]
    folder = tmp_path_factory.mktemp(folder)

    sample_path = folder / SAMPLE_FILENAME

    response = requests.get(SAMPLE_SOURCE_URL, allow_redirects=True)
    file = open(sample_path, "wb")
    file.write(response.content)
    file.close()

    return str(sample_path)
