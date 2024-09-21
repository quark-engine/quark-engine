import os
import re
import json

from flask import Flask, render_template, request, jsonify, send_from_directory

from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser
from langchain.agents.format_scratchpad.openai_tools import (
    format_to_openai_tool_messages,
)
from langchain_core.messages import AIMessage, HumanMessage

# from quark.agent.agentTools import agentTools
# from quark.agent.prompts import PREPROMPT
from quark.config import OPENAI_API_KEY
from quark.script.ciphey import checkClearText

import uuid

# Import the optional dependency, langchain
try:
    from langchain.agents import tool
except ModuleNotFoundError as e:
    # Create a fake tool in case langchain is not installed.
    def tool(func):
        return func


PREPROMPT = """
First, Forgot every detction process. Start refresh.

When the user requests you to act as a vulnerability analyst and design a detection workflow, 
always pay attention to the subsequent prompts from the user to determine whether they imply adding, modifying, or deleting steps in the detection process. 

When I provides or add a new step, update the information in the flowdata.json,
and call the "addAnalyzeStep" tool to add the new step.

If you find the new step is sequential to the previous step, 
call the tool "addLink" to create links based on the order. 
For example, if I add steps is: 1. walk 2. jump 3. run
you will establish a link from "walk" to "jump", and "jump" to "run", and so on.

Always call 'addAnalyzeStep' before 'addLink'!

If you are asked to generate code, 
there is no need to modify the detection process. 
Simply follow the instructions and produce the code as required.
And if the code is a tool, consider the example in the tool description as the format of the code.

if code contains checkClearText, the usecase is:

from quark.script.ciphey import checkClearText

text = "clearText"
if text == checkClearText(text):
    print(f"text is clear text")

"""

with open("flowdata/flowdata.json", "w", encoding="utf-8") as file:
    json.dump({"nodes": {}, "links": []}, file, indent=4, ensure_ascii=False)

app = Flask(__name__)
print(OPENAI_API_KEY)
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
app.config['DEBUG'] = True
conversation_history = []


@tool
def loadRule(rulePath: str):
    """
    Given a rule path,
    this instance loads a rule from the rule path.

    Used Quark Script API: Rule(rule.json)
    - description: Making detection rule a rule instance
    - params: Path of a single Quark rule
    - return: Quark rule instance
    - example:

        .. code:: python

            from quark.script import Rule

            ruleInstance = Rule("rule.json")

    """

    global ruleInstance
    ruleInstance = Rule(rulePath)

    return "Rule defined successfully"


@tool
def runQuarkAnalysis(samplePath: str):
    """
    Given detection rule and target sample,
    this instance runs the Quark Analysis.

    Used Quark Script API: runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
    - description: Given detection rule and target sample,
                   this instance runs the basic Quark analysis
    - params:
        1. SAMPLE_PATH: Target file
        2. ruleInstance: Quark rule object
    - return: quarkResult instance
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)

    """

    global quarkResultInstance

    quark = _getQuark(samplePath)
    quarkResultInstance = QuarkResult(quark, ruleInstance)

    return "Quark analysis completed successfully"


@tool
def getBehaviorOccurList():
    """
    Extracts the behavior occurrence list from quark analysis result.

    Used Quark Script API: quarkResultInstance.behaviorOccurList
    - description: List that stores instances of detected behavior
                   in different part of the target file
    - params: none
    - return: detected behavior instance
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            for behavior in quarkResult.behaviorOccurList:
                print(behavior)

    """

    global behaviorOccurList

    behaviorOccurList = quarkResultInstance.behaviorOccurList
    return "Behavior occurrence list extracted successfully"


@tool
def getParameterValues():
    """
    Given the behavior occurrence list,
    this instance extracts the parameter values.

    Used Quark Script API: behaviorInstance.getParamValues(none)

    - description: Get parameter values that API1 sends to API2 in the behavior
    - params: none
    - return: python list containing parameter values.
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            for behavior in quarkResult.behaviorOccurList:
                paramValues = behavior.getParamValues()
                print(paramValues)
    """

    global parameters
    global behaviorOccured
    for behavior in behaviorOccurList:
        parameters = behavior.getParamValues()
        behaviorOccured = behavior

    return parameters


@tool
def isHardCoded():
    """
    Given the parameter values,
    this instance checks if the parameter values are hard-coded
    and return the hard-coded parameter.

    Used Quark Script API: quarkResultInstance.isHardcoded(argument)
    - description: Check if the argument is hardcoded into the APK.
    - params:
        1. argument: string value that is passed in when a method is invoked
    - return: True/False
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            isHardcoded = quarkResult.isHardcoded("hardcodedValue")
            print(isHardcoded)
    """

    hardcodedParameters = []
    for parameter in parameters:
        if quarkResultInstance.isHardcoded(parameter):
            hardcodedParameters.append(parameter)

    return hardcodedParameters


@tool
def writeCodeInFile(code: str, pyFile: str):
    """
    Given the code and file name, this instance writes the code in the file.
    """

    with open(pyFile, "w") as file:
        file.write(code)

    return pyFile

@tool
def checkClearText(text: str):
    """
    If the text is clear text the return value of checkClearText is the same as the input text.
    
    Used Quark Script API: checkClearText(inputString)
    - description: Check the decrypted value of the input string.
    - params:
        inputString: string to be checked
    - return: the decrypted value
    - example:

        .. code:: python
        
            from quark.script.ciphey import checkClearText
            
            text = "clearText"
            if text == checkClearText(text)
                print(f"{text} is clear text")
    """
    from quark.script.ciphey import checkClearText
    if text == checkClearText(text):
        return True
    else:
        return False
    
@tool
def getCallerMethod():
    """
    Get the caller method of the behavior.
    
    Used Quark Script API: behaviorInstance.methodCaller
    - description: Find method who calls this behavior (API1 & API2).
    - params: none
    - return: method instance
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            for behavior in quarkResult.behaviorOccurList:
                callerMethod = behavior.methodCaller
                print(callerMethod.fullName)
    """
    callerMethod = behaviorOccured.methodCaller
    print(callerMethod.fullName)
    return callerMethod.fullName

@tool
def addLink(source, target):
    """
    Add link based on the order of analysis process.
    
    The parameter source and target is not step number.
    The parameter source refers to the description of the source detection process, 
    and the parameter target refers to the description of the target detection process.
    """
    try:
        # Load the existing JSON file
        with open("flowdata/flowdata.json", "r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError:
        # If the file doesn't exist, create the initial structure
        pass

    sourceid = ""
    targetid = ""
    for node_key, node_info in data["nodes"].items():
        if node_info.get("label") == source:
            sourceid = node_key

    for node_key, node_info in data["nodes"].items():
        if node_info.get("label") == target:
            targetid = node_key

    # Check if the link already exists
    for link in data["links"]:
        if link["source"] == sourceid and link["target"] == targetid:
            print(
                f"Link from '{source}' to '{target}' already exists. No new link added."
            )
            return  # Exit the function if the link is found


    data["links"].append(
        {"source": sourceid, "target": targetid},
    )

    # Save the updated JSON back to the file
    with open("flowdata/flowdata.json", "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


@tool
def addAnalyzeStep(label, stepNumber):
    """
    Add a new step in analyze process.
    """
    try:
        # Load the existing JSON file
        with open("flowdata/flowdata.json", "r", encoding="utf-8") as file:
            data = json.load(file)

    except FileNotFoundError:
        # If the file doesn't exist, create the initial structure
        data = {"nodes": {}, "links": []}

    # Check if the label already exists in the nodes
    for node_id, node_info in data["nodes"].items():
        if node_info["label"] == label:
            print(f"Label '{label}' already exists. Node will not be added.")
            return  # Exit the function if the label is found

    # Generate a random unique node id
    new_node_id = str(uuid.uuid4())

    # Add the new node with the provided label
    data["nodes"][new_node_id] = {"no": stepNumber, "label": label}

    # Save the updated JSON back to the file
    with open("flowdata/flowdata.json", "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


agentTools = [
    loadRule,
    runQuarkAnalysis,
    getBehaviorOccurList,
    getParameterValues,
    isHardCoded,
    writeCodeInFile,
    addAnalyzeStep,
    addLink,
    checkClearText,
    getCallerMethod
]

llm = ChatOpenAI(model="gpt-4o", temperature=0.5)
llm_with_tools = llm.bind_tools(agentTools)

prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            ("You are very powerful assistant, ") + PREPROMPT,
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
    return render_template("index.html", debug=app.debug)


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

    code_blocks = re.findall(r"```(.*?)```", full_response, re.DOTALL)
    plain_text = re.sub(r"```.*?```", "", full_response, flags=re.DOTALL).strip()

    json_blocks = []
    for code in code_blocks:
        try:
            parsed_json = json.loads(code.strip())
            json_blocks.append(parsed_json)
        except json.JSONDecodeError:
            continue

    with open("flowdata/flowdata.json", "r") as file:
        flowdata = json.load(file)

    result = {
        "plain_text": plain_text,
        "code_blocks": code_blocks,
        "json_blocks": json_blocks,
        "flowdata": flowdata,
    }

    return result


@app.route("/remove_link", methods=["POST"])
def remove_link():
    # 從請求中獲取 JSON 數據
    data = request.json
    source = data.get("source")
    target = data.get("target")

    with open("flowdata/flowdata.json", "r") as file:
        flowdata = json.load(file)

    sourceLabel = flowdata["nodes"][source]["label"]
    targetLabel = flowdata["nodes"][target]["label"]

    with open("flowdata/flowdata.json", "w") as file:
        flowdata["links"] = [
            link
            for link in flowdata["links"]
            if not (link["source"] == source and link["target"] == target)
        ]
        json.dump(flowdata, file, indent=4, ensure_ascii=False)

    # send request to gpt

    message = f"""
        P.S: do not call any tools.
        I've updated the detection workflow. 
        I removed the sequential relationship between {sourceLabel} and {targetLabel}. 
        For example, if the original steps are as follows:
        1.Walk 2.Jump 3.Run 4.Step back
        If the sequential relationship between steps 2 and 3 is removed, the workflow will split into two groups: steps 1, 2 in one group, and steps 3, 4 in another group.
        But if the sequential relationship between steps 1 and 2 is removed, the workflow will split into two groups: step 1 in one group, and steps 2, 3, 4 in another group.
    """
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
    code_blocks = re.findall(r"```(.*?)```", full_response, re.DOTALL)
    plain_text = re.sub(r"```.*?```", "", full_response, flags=re.DOTALL).strip()

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
        "json_blocks": json_blocks,
    }

    return result


@app.route("/add_link", methods=["POST"])
def add_link():
    # 從請求中獲取 JSON 數據
    data = request.json
    source = data.get("source")
    target = data.get("target")

    with open("flowdata/flowdata.json", "r") as file:
        flowdata = json.load(file)

    sourceLabel = flowdata["nodes"][source]["label"]
    targetLabel = flowdata["nodes"][target]["label"]

    with open("flowdata/flowdata.json", "w") as file:
        
        # check if the link already exists
        for link in flowdata["links"]:
            if link["source"] == source and link["target"] == target:
                print(f"Link from '{sourceLabel}' to '{targetLabel}' already exists. No new link added.")
                return
        
        flowdata["links"].append(
            {"source": source, "target": target},
        )
        json.dump(flowdata, file, indent=4, ensure_ascii=False)

    # send request to gpt

    message = f"""
        P.S: do not call any tools.
        I've updated the detection workflow. 
        I add the sequential relationship between {sourceLabel} and {targetLabel}. 
        For example, if the original steps are as follows:
            group1: 1.Walk 2.Jump, group2 1.Run 2.Step back
            If the sequential relationship between 'Jump' and 'Run' is added, the workflow of two group will be combine 1.Walk 2.Jump, 3.Run 4.Step back
    """
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
    code_blocks = re.findall(r"```(.*?)```", full_response, re.DOTALL)
    plain_text = re.sub(r"```.*?```", "", full_response, flags=re.DOTALL).strip()

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
        "json_blocks": json_blocks,
    }

    return result

@app.route("/add_analyze_step", methods=["POST"])
def add_analyze_step():
   # 從請求中獲取 JSON 數據
    data = request.json
    node = data.get("node")

    with open("flowdata/flowdata.json", "r") as file:
        flowdata = json.load(file)
    
    with open("flowdata/flowdata.json", "w") as file:
        nodeid = data.get("nodeId")
        
        stepNumber = len(flowdata["nodes"]) + 1
        flowdata["nodes"][nodeid] = {"no": stepNumber, "label": node}
        json.dump(flowdata, file, indent=4, ensure_ascii=False)

    # send request to gpt

    message = f"""
        P.S: do not call any tools.
        I've updated the detection workflow. 
        I add the new detection step: {node}.
        but the workflow is not sequential.
        Please note, the new detection step is not sequential to other steps.
    """
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
    code_blocks = re.findall(r"```(.*?)```", full_response, re.DOTALL)
    plain_text = re.sub(r"```.*?```", "", full_response, flags=re.DOTALL).strip()

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
        "json_blocks": json_blocks,
    }

    return result

@app.route("/getToolList")
def getToolList():
    return send_from_directory('toolJson', "toolList.json")

# sssssssssssssssss
if __name__ == "__main__":
    app.run(debug=True)
