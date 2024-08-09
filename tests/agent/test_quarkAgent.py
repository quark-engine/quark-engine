import os
import pytest

from click.testing import CliRunner
from quark.agent.quarkAgent import entryPoint
from tests.agent.conftest import reload


@pytest.fixture(scope="function")
def apiKeyInEnv():
    if "OPENAI_API_KEY" not in os.environ:
        os.environ["OPENAI_API_KEY"] = "API-key-for-unit-tests"
        yield
        del os.environ["OPENAI_API_KEY"]


def testImportQuarkAgentWithoutLangChain(missingLangchain):
    reload("quark.agent.agentTools")


def testEntryPointWithoutLangChain(missingLangchain):
    runner = CliRunner()
    result = runner.invoke(entryPoint)

    assert result.output
    assert not result.exception


def testEntryPointWithAPIKeyInEnv():
    runner = CliRunner()
    result = runner.invoke(
        entryPoint,
        input="bye\n",
        env={"OPENAI_API_KEY": "API-key-for-unit-tests"},
    )

    assert "User Input: " == result.output
    assert not result.exception


def testEntryPointWithAPIKeyAsArg():
    runner = CliRunner()
    result = runner.invoke(
        entryPoint, args=["--api-key", "API-key-for-unit-tests"], input="bye\n"
    )

    assert "User Input: " == result.output
    assert not result.exception


def testEntryPointWithAPIKeyAskInput():
    runner = CliRunner()
    result = runner.invoke(entryPoint, input="API-key-for-unit-tests\nbye\n")

    assert "User Input: " in result.output
    assert not result.exception
