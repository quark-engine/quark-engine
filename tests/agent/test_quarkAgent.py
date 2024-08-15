from click.testing import CliRunner
from quark.agent.quarkAgent import entryPoint
from tests.agent.conftest import reload


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

    assert "User Input: " in result.output
    assert not result.exception
