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

   .. code-block::

      git clone https://github.com/quark-engine/quark-script.git

2. Install the required packages:

   .. code-block::

      pip install -r requirements.txt

3. Add your OpenAI API key in quarkscriptAgent.py.

   .. code-block:: python

      os.environ["OPENAI_API_KEY"] = {your API Key}

4. Run the script:

   .. code-block::

      python quarkScriptAgent.py

5. Result:

.. image:: https://github.com/user-attachments/assets/9c8ba9d3-c8b5-4583-8cb8-750f8c3bf2a7


Decode the Prompts
~~~~~~~~~~~~~~~~~~

Here are two prompts, each for executing different analysis processes.

.. code:: TEXT

   1st Prompt: Initialize the rule instance with the rule path set to "constructCryptoGraphicKey.json"

Used Quark Script APIs/Tools that LLM used: ``loadRule``

.. code:: TEXT

   2nd Prompt: Run Quark Analysis using the rule instance on the apk sample "ovaa.apk", 
               and Check if the parameters are hard-coded. If yes, display the hard-coded values.

Used Quark Script APIs/Tools that LLM used: ``runQuarkAnalysis``,
``getBehaviorOccurList``, ``getParameterValues`` and ``isHardCoded``

The ``loadRule``, ``runQuarkAnalysis``, ``getBehaviorOccurList``,
``getParameterValues``, and ``isHardCoded`` functions are treated as
**tools** within LangChain, enabling them to be invoked through the
``gpt-4o`` model to analyze and identify
`CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`__ vulnerabilities in the `ovaa.apk <https://github.com/oversecured/ovaa>`__ sample.

.. image:: https://hackmd.io/_uploads/BkplMjvYR.png



Showcase: Generating Quark Script with Quark Script Agent
---------------------------------------------------------

Quark Script Agent allows you to automate the creation of Quark Script code. This lets users concentrate on designing the detection process, while the LLM and Quark Script API handle the coding. This approach greatly enhances efficiency and streamlines the workflow.

Here's an example for generating a Quark Script to detect CWE-798.

Demo Video
~~~~~~~~~~

.. raw:: html

   <iframe src="https://github.com/user-attachments/assets/dc0e782b-3500-4260-a961-c499c14e495c" width="700" height="300" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"></iframe>



Decode the Prompts
~~~~~~~~~~~~~~~~~~

Now, let's instruct the Quark Script Agent to detect CWE-798 and write the Quark Script for the detection process using the following prompt.

**Assign a role to the Agent**

To make the Quark Script Agent's responses more precise and relevant to vulnerability detection, we assign it the role of an Android APK vulnerability analyst.

.. code-block:: TEXT

   User: 
   Now you are an Android APK vulnerability analyst. Please follow the steps below to analyze a sample.

.. code-block:: TEXT

   Agent: 
   Sure, I'd be happy to help with that. Please provide the sample APK file and the detection rule file that you would like to use for the analysis.


**Instruct the detection process**

Instruct the Quark Script Agent to detect CWE-798 using the following detection process.

.. code-block:: TEXT

   Detection Process:
   1. Define the behavior "Construct Cryptographic Key" in the rule instance.
   2. Run Quark Analysis using the rule instance on the APK sample.
   3. Obtain all instances of detected behaviors from the Quark Analysis results.
   4. Retrieve the parameter values for each occurred behavior.
   5. Check if any parameters are hard-coded. If found, print the hard-coded parameters.

..

.. note::
   
   The prompt will include details like the sample or rule path.



1. Define the behavior "Construct Cryptographic Key" in the rule instance.
 
.. code-block:: TEXT
   
   User: 
   1. Define the behavior "Construct Cryptographic Key" in the rule instance, with the rule path set to "constructCryptoGraphicKey.json".


.. code-block:: TEXT

   Agent: 
   The behavior "Construct Cryptographic Key" has been successfully defined in the rule instance with the rule path set to "constructCryptoGraphicKey.json". How would you like to proceed?


2. Run Quark Analysis using the rule instance on the APK sample.

.. code-block:: TEXT
   
   User:
   2. Run Quark Analysis using the rule instance on the APK sample "ovaa.apk".


.. code-block:: TEXT

   Agent:
   The Quark analysis on the APK sample "ovaa.apk" has been completed successfully. What would you like to do next?


3. Obtain all instances of detected behaviors from the Quark Analysis results.
   
.. code-block:: TEXT
   
   User:
   3. Obtain all instances of detected behaviors from the Quark Analysis results in the sample "ovaa.apk".


.. code-block:: TEXT

   Agent
   I have obtained all instances of detected behaviors from the Quark Analysis results in the sample "ovaa.apk". If you need further details or specific information about these behaviors, please let me know!


4. Retrieve the parameter values for each occurred behavior.

.. code-block:: TEXT
   
   User:
   4. Retrieve the parameter values for each occurred behavior.


.. code-block:: TEXT

   Agent:
   The parameter values for the occurred behavior are:
   1. "49u5gh249gh24985ghf429gh4ch8f23f"
   2. "AES"

   Would you like to check if any of these values are hard-coded?


5. Check if any parameters are hard-coded. If found, print the hard-coded parameters.

.. code-block:: TEXT
   
   User:
   5. Check if any parameter values are hard-coded. If yes, display the hard-coded values.


.. code-block:: TEXT

   Agent:
   The following parameter values are hard-coded:

   1. `49u5gh249gh24985ghf429gh4ch8f23f`
   2. `AES`


**Generate Quark Script**

Finally, ask the Quark Script Agent to write and execute the Python code based on the detection process outlined above.

.. code-block:: TEXT

   User:
   Using the Quark Script API, implement the above logic in Python and save it to 'detectCWE798.py', with the rule path set to 'constructCryptoGraphicKey.json' and the sample path to 'ovaa.apk'.


.. code-block:: TEXT

   Agent:
   The code has been written to `detectCWE798.py`. You can now execute this script to perform the analysis.


Here is the generated code:

.. code-block:: python

   from quark.script import Rule, runQuarkAnalysis

   # Load the rule
   rule_path = 'constructCryptoGraphicKey.json'
   rule_instance = Rule(rule_path)

   # Define the sample path
   sample_path = 'ovaa.apk'

   # Run the Quark analysis
   quark_result = runQuarkAnalysis(sample_path, rule_instance)

   # Extract the behavior occurrence list
   behavior_occur_list = quark_result.behaviorOccurList

   # Iterate through each behavior and get parameter values
   for behavior in behavior_occur_list:
       param_values = behavior.getParamValues()
       for param in param_values:
           # Check if the parameter value is hardcoded
           is_hardcoded = quark_result.isHardcoded(param)
           if is_hardcoded:
               print(f'Hardcoded value found: {param}')


.. code-block:: TEXT

   User:
   Execute detectCWE798.py


Here is the result.

.. code-block:: shell

   Hardcoded value found: 49u5gh249gh24985ghf429gh4ch8f23f
   Hardcoded value found: AES


We added 2 tools, ``writeCodeInFile`` and ``executeCode`` , to enable Quark Script Agent to generate and execute Quark Script code.

.. image:: https://github.com/user-attachments/assets/d8fd805a-86c9-4eff-b120-d340fc43d792


.. note::
   1. The code is generated by OpenAI's GPT model, and the output may not always match the documentation exactly.
   2. Since LangChain currently does not support passing Python
      instances between tools, we are temporarily using global variables
      to pass parameters between tools in ``quarkScriptAgent.py``.
   3. Place the rules, samples, and ``quarkScriptAgent.py`` in the same
      folder; the LLM will automatically find files with matching names.
   4. A web GUI is under construction, please stay tuned!
