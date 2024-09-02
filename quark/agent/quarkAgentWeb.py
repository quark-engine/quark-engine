
import os
import re
import json

from flask import Flask, render_template, request

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser
from langchain.agents.format_scratchpad.openai_tools import (
    format_to_openai_tool_messages,
)
from langchain_core.messages import AIMessage, HumanMessage
from quark.agent.agentTools import agentTools
from quark.agent.prompts import PREPROMPT

app = Flask(__name__)

os.environ["OPENAI_API_KEY"] = ''

conversation_history = []


llm = ChatOpenAI(model="gpt-4o", temperature=0.2)
llm_with_tools = llm.bind_tools(agentTools)

prompt = ChatPromptTemplate.from_messages(
    [
        (
                "system",
                (
                    "You are very powerful assistant, "
                    + "but don't know current events"
                ) + PREPROMPT,
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
    | llm_with_tools
    | OpenAIToolsAgentOutputParser()
)

agent_executor = AgentExecutor(agent=agent, tools=agentTools, verbose=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/get_response")
def get_response():
    message = request.args.get("message")
    conversation_history.append(message)

    response = agent_executor.invoke(
        {"input": message, "chat_history": conversation_history}
    )

    conversation_history.extend(
        [
            HumanMessage(content=message),
            AIMessage(content=response["output"]),
        ]
    )

    full_response = response["output"]
    conversation_history.append(full_response)

    code_blocks = re.findall(r'```(.*?)```', full_response, re.DOTALL)
    plain_text = re.sub(r'```.*?```', '', full_response,
                        flags=re.DOTALL).strip()

    json_blocks = []
    for code in code_blocks:
        try:
            parsed_json = json.loads(code.strip())
            json_blocks.append(parsed_json)
        except json.JSONDecodeError:
            continue

    result = {
        "plain_text": plain_text,
        "code_blocks": code_blocks,
        "json_blocks": json_blocks
    }

    return result


if __name__ == "__main__":
    app.run()
