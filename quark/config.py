# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from pathlib import Path

HOME_DIR = f"{Path.home()}/.quark-engine/"
SOURCE = "https://github.com/quark-engine/quark-rules"
DIR_PATH = f"{HOME_DIR}quark-rules"

DEBUG = False
COMPATIBLE_RAZIN_VERSIONS = ["0.3.4"]

RIZIN_DIR = f"{HOME_DIR}rizin/"
RIZIN_COMMIT = "2373c53880e017be86afed5454bca5b5017b920e"

Path(HOME_DIR).mkdir(parents=True, exist_ok=True)
