Quark Script Agent
==================

Introducing Quark’s new member, the Quark Script Agent, the first AI
assistant in the Quark team. This agent enables users to perform
analyses using natural language, without the need for programming or
scripting expertise, making the process simple and user-friendly.

The Quark Script Agent integrates with LangChain, which utilizes
OpenAI’s large language models to act as a bridge between natural
language and the Quark Script API. LangChain defines the Quark Script
API as a tool that large language models can understand and use. This
means that users can easily call new analysis APIs using natural
language commands by simply adding new tools as needed.

Showcase: Detecting CWE-798 with Quark Script Agent
---------------------------------------------------

Here’s an example of using the Quark Script Agent with the
``quarkScriptAgent.py``. This agent can currently detect
`CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`__
vulnerability in the `ovaa.apk <https://github.com/oversecured/ovaa>`__.
See the details below.

Quick Start
~~~~~~~~~~~

1. clone the repository:

::

   git clone https://github.com/quark-engine/quark-script.git

2. Install the required packages:

::

   pip install -r requirements.txt

3. Run the script:

::

   python quarkScriptAgent.py

4. Result:

.. image:: https://github.com/user-attachments/assets/9c8ba9d3-c8b5-4583-8cb8-750f8c3bf2a7

Decode the Prompts
~~~~~~~~~~~~~~~~~~

Here are two prompts, each for executing different analysis processes.

::

   1st Prompt: Initialize the rule instance with the rule path set to "rule.json"

Used Quark Script APIs/Tools that LLM used: ``loadRule``

::

   2nd Prompt: Run Quark Analysis using the rule instance on the apk sample "ovaa.apk", 
               and Check if the parameters are hard-coded. If yes, display the hard-coded values.

Used Quark Script APIs/Tools that LLM used: ``runQuarkAnalysis``,
``getBehaviorOccurList``, ``getParameterValues`` and ``isHardCoded``

The ``loadRule``, ``runQuarkAnalysis``, ``getBehaviorOccurList``,
``getParameterValues``, and ``isHardCoded`` functions are treated as
**tools** within LangChain, enabling them to be invoked through the
``gpt-4o`` model to analyze and identify
`CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`__
vulnerabilities in the
`ovaa.apk <https://github.com/oversecured/ovaa>`__ sample.

.. image:: https://github.com/user-attachments/assets/1dd8fb68-9ab4-4afc-a15a-006ff468a883

.. note::

   1. Since LangChain currently does not support passing Python
      instances between tools, we are temporarily using global variables
      to pass parameters between tools in ``quarkScriptAgent.py``.
   2. Place the rules, samples, and ``quarkScriptAgent.py`` in the same
      folder; the LLM will automatically find files with matching names.
   3. A web GUI is under construction, please stay tuned!
