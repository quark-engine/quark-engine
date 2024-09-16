# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
import click
from quark.utils.colors import green, cyan


def __printDependencyMissingMessage() -> None:
    print("Quark Agent requires langchain and its OpenAI integration to work.")
    print(
        (
            "Please use the command 'python3 -m pip install"
            " langchain langchain-core langchain-openai --upgrade'"
            " to install the packages."
        )
    )


def __setOrAskAPIKey(apiKey: str) -> bool:
    if apiKey:
        os.environ["OPENAI_API_KEY"] = apiKey
    elif "OPENAI_API_KEY" not in os.environ:
        try:
            os.environ["OPENAI_API_KEY"] = click.prompt(
                "Please provide the access key of OpenAI API"
            )
        except click.Abort:
            return False

    return True


@click.command()
@click.option(
    "--api-key",
    help="Access key of OpenAI API",
    type=str,
    show_default=False,
    default=None,
)
def entryPoint(api_key: str) -> None:

    try:
        from langchain_openai import ChatOpenAI
        from langchain.agents import AgentExecutor
        from langchain_core.prompts import (
            ChatPromptTemplate,
            MessagesPlaceholder,
        )
        from langchain_core.messages import AIMessage, HumanMessage
        from langchain.agents.output_parsers.openai_tools import (
            OpenAIToolsAgentOutputParser,
        )
        from langchain.agents.format_scratchpad.openai_tools import (
            format_to_openai_tool_messages,
        )
    except ModuleNotFoundError:
        __printDependencyMissingMessage()
        # langchain is not installed.
        return

    from quark.agent.agentTools import agentTools
    from quark.agent.prompts import SUMMARY_REPORT_FORMAT

    if not __setOrAskAPIKey(api_key):
        # OpenAI API Key is not provided.
        return

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.8)
    llmWithTools = llm.bind_tools(agentTools)

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                (
                    "You are very powerful assistant, "
                    + "but don't know current events"
                )
                + SUMMARY_REPORT_FORMAT,
            ),
            MessagesPlaceholder(variable_name="chat_history"),
            ("user", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ]
    )

    agent = (
        {
            "input": lambda x: x["input"],
            "agent_scratchpad": lambda x: format_to_openai_tool_messages(
                x["intermediate_steps"]
            ),
            "chat_history": lambda x: x["chat_history"],
        }
        | prompt
        | llmWithTools
        | OpenAIToolsAgentOutputParser()
    )

    agentExecutor = AgentExecutor(agent=agent, tools=agentTools, verbose=False)

    conversationHistory = []

    try:
        inputText = input(green("User Input: "))
        while inputText.lower() != "bye":
            if inputText:
                response = agentExecutor.invoke(
                    {"input": inputText, "chat_history": conversationHistory}
                )

                conversationHistory.extend(
                    [
                        HumanMessage(content=inputText),
                        AIMessage(content=response["output"]),
                    ]
                )

                print()
                print(cyan("Agent: "), response["output"])
                print()

            inputText = input(green("User Input: "))
    except click.Abort:
        return


if __name__ == "__main__":
    entryPoint()  # pylint: disable=E1120
