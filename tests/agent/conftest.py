import builtins
import sys
import pytest
import importlib

from typing import Mapping, Sequence, Union


@pytest.fixture(scope="function")
def missingLangchain(monkeypatch):
    # Unload langchain if langchain is imported.
    originalLangChain = sys.modules.get("langchain", None)
    if originalLangChain:
        del sys.modules["langchain"]

    # Mock the keyword, import
    builtinImport = builtins.__import__

    def mockedImport(
        name: str,
        globals: Union[Mapping[str, object], None] = None,
        locals: Union[Mapping[str, object], None] = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ):
        if name.startswith("langchain"):
            raise ModuleNotFoundError()
        else:
            return builtinImport(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", mockedImport)

    yield

    # Reload langchain if langchain was imported.
    if originalLangChain:
        sys.modules["langchain"] = originalLangChain


def reload(module: str) -> None:
    originalModule = sys.modules.get(module, None)
    if originalModule:
        del sys.modules[module]

    importlib.import_module(module)

    if originalModule:
        sys.modules[module] = originalModule
