###########
Quark Agent
###########

Introducing Quark's new member, Quark Agent, the AI assistant in the Quark team. This agent lets users perform Quark analysis using natural language, eliminating the need for scripting expertise or terminal commands, which makes the analysis simple and user-friendly.

Quark Agent integrates with LangChain, using OpenAI's large language model to act as a bridge between the natural language and the Quark/Quark Script APIs. LangChain defines these APIs as tools that large language models can understand and use. This means users can run Quark analysis using natural language by simply adding new tools as needed.

Below are showcases of using Quark Agent for vulnerability and malware analysis.

**********************
Vulnerability Analysis
**********************

Showcase: Detecting CWE-798 with Quark Agent
---------------------------------------------------

This example uses Quark Agent to detect `CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`__ vulnerability in `ovaa.apk <https://github.com/oversecured/ovaa>`__. See the details below.

Quick Start
~~~~~~~~~~~

1. Clone the repository:

   .. code-block::

      git clone https://github.com/quark-engine/quark-script.git

2. Install the required packages:

   .. code-block::

      pip install -r requirements.txt

3. Add your OpenAI API key in quarkScriptAgent.py.

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


Showcase: Generating Quark Script with Quark Agent
---------------------------------------------------------

Quark Agent allows you to automate the creation of Quark Script code. This lets users concentrate on designing the detection process, while the LLM and Quark Script API handle the coding. This approach greatly enhances efficiency and streamlines the workflow.

Here's an example for generating a Quark Script to detect CWE-798.

Demo Video
~~~~~~~~~~

.. raw:: html

   <iframe src="https://github.com/user-attachments/assets/dc0e782b-3500-4260-a961-c499c14e495c" width="700" height="300" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"></iframe>



Decode the Prompts
~~~~~~~~~~~~~~~~~~

Now, let's instruct Quark Agent to detect CWE-798 and write the Quark Script for the detection process using the following prompt.

**Assign a role to the Agent**

To make Quark Agent's responses more precise and relevant to vulnerability detection, we assign it the role of an Android APK vulnerability analyst.

.. code-block:: TEXT

   User: 
   Now you are an Android APK vulnerability analyst. Please follow the steps below to analyze a sample.

.. code-block:: TEXT

   Agent: 
   Sure, I'd be happy to help with that. Please provide the sample APK file and the detection rule file that you would like to use for the analysis.


**Instruct the detection process**

Instruct Quark Agent to detect CWE-798 using the following detection process.

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

Finally, ask Quark Agent to write and execute the Python code based on the detection process outlined above.

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


We added 2 tools, ``writeCodeInFile`` and ``executeCode`` , to enable Quark Agent to generate and execute Quark Script code.

.. image:: https://github.com/user-attachments/assets/d8fd805a-86c9-4eff-b120-d340fc43d792


.. note::
   1. The code is generated by OpenAI's GPT model, and the output may not always match the documentation exactly.
   2. Since LangChain currently does not support passing Python
      instances between tools, we are temporarily using global variables
      to pass parameters between tools in ``quarkScriptAgent.py``.
   3. Place the rules, samples, and ``quarkScriptAgent.py`` in the same
      folder; the LLM will automatically find files with matching names.
   4. A web GUI is under construction, please stay tuned!

****************
Malware Analysis
****************

Showcase: Generate Summary Report with Quark Agent
--------------------------------------------------

This example uses Quark Agent to analyze `ovaa.apk <https://github.com/oversecured/ovaa>`__ and generate a :ref:`summary report <summary-report>`. See the details below.

Quick Start
~~~~~~~~~~~

1. Install Quark Agent:

   .. code-block:: shell

      git clone https://github.com/quark-engine/quark-engine.git & cd quark-engine
      pip install .[QuarkAgent]

2. Prepare the rule and the sample:

   .. code-block:: shell

      git clone https://github.com/quark-engine/quark-script
      cd quark-script

3. Add your OpenAI API key to the environment:

   .. code-block:: python

      export OPENAI_API_KEY='your-api-key-here'

4. Run Quark Agent:

   .. code-block:: shell

      quark-agent

5. Result:

.. image:: https://github.com/user-attachments/assets/46407664-de0d-4849-8995-642ff636d71e


Decode the Prompts
~~~~~~~~~~~~~~~~~~

Here, we explain what happens after running Quark Agent.

**Preset Prompt**

To ensure the ``gpt-4o-mini`` model follows the correct format of a summary report, we designed the following preset prompt and hard-coded it into Quark Agent.

When Quark Agent starts, it will automatically pass the preset prompt to the ``gpt-4o-mini`` model. Hence, we don't need to pass this prompt manually.

.. code:: TEXT

    Preset Prompt:

    When prompted to provide a summary report, follow these rules and the summary report example:

      1. Print a newline character first to prevent formatting issues.
      2. Change "<RISK_LEVEL>" in "WARNING: <RISK_LEVEL>" to the risk level with the first letter of each word capitalized.
      3. Change "<TOTAL_SCORE>" in "Total Score: <TOTAL_SCORE>" to the total score, expressed as a decimal numeral.
      4. Without using a code block, place the output of the tool, getSummaryReportTable, in the line directly after "Total Score: <TOTAL_SCORE>".

    The Summary Report Example:

    [!] WARNING: <RISK_LEVEL>
    [*] Total Score: <TOTAL_SCORE>
    +--------------------------------+-----------------------------+------------+-------+--------+  
    | Filename                       | Rule                        | Confidence | Score | Weight |  
    +--------------------------------+-----------------------------+------------+-------+--------+  
    | constructCryptoGraphicKey.json | Construct cryptographic key | 100%       | 1     | 1.0    |  
    +--------------------------------+-----------------------------+------------+-------+--------+ 

    Ensure you adhere to these rules and the example when providing a summary report.

**User Prompts**

Then, by passing the following prompt manually, we ask Quark Agent to analyze the `ovaa.apk <https://github.com/oversecured/ovaa>`__ sample and generate a summary report. 

.. code:: TEXT

   1st Prompt: Analyze the sample “ovaa.apk” using Quark and the rule “constructCryptoGraphicKey.json.”
               After the analysis, print the summary report.

Used Quark APIs/Tools that LLM used: ``initRuleObject``, ``initQuarkObject``, ``runQuarkAnalysisForSummaryReport``, ``getSummaryReportTable``, ``getAnalysisResultRisk``, and ``getAnalysisResultScore``

To highlight the analysis result, we ask Quark Agent to colorize the summary report.

.. code:: TEXT

   2nd Prompt: Colorize "[!]" in yellow, "[*]" in cyan, the "Rule" column and its data in green,
               the "Confidence" column and its data in yellow, and the "Weight" column and its data in red.

Used Quark APIs/Tools that LLM used: ``colorizeInYellow``, ``colorizeInCyan``, ``colorizeInGreen``, and ``colorizeInRed``



All APIs above are treated as tools within LangChain, enabling them to be invoked through the ``gpt-4o-min`` model to analyze the `ovaa.apk <https://github.com/oversecured/ovaa>`__ sample and generate a colorized summary report.

.. image:: https://github.com/user-attachments/assets/656e8dcb-b0b6-4b02-bc06-58b2b01d054b

Showcase: Enhance Summary Report with Quark Agent
----------------------------------------------------

Quark Agent can enhance the summary report by refining Quark's risk assessment mechanism. With user instructions, it can adjust the scores, weights, and risk of the sample based on its understanding of Quark analysis and rules, enabling users to identify high-risk samples and locate critical behaviors accurately.

Here's an example that enhances the summary report of `Ahmyth.apk <https://github.com/quark-engine/apk-samples/blob/master/malware-samples/Ahmyth.apk>`__ .

Demo Video
~~~~~~~~~~

.. raw:: html

   <iframe src="https://github.com/user-attachments/assets/79023381-6b35-471f-8e49-10d654e40fa1" width="700" height="370" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"></iframe>



Decode the Prompts
~~~~~~~~~~~~~~~~~~

Now, let's explain what happens after running Quark Agent.

**Generate a summary report**

We ask Quark Agent to generate a summary report for `Ahmyth.apk <https://github.com/quark-engine/apk-samples/blob/master/malware-samples/Ahmyth.apk>`__.

.. code-block:: TEXT

   User: 
   Analyze the sample “Ahmyth.apk” using Quark and the rules in the directory “rules.” After the analysis, print the summary report.

.. code-block:: TEXT

   Agent: 
   [!] WARNING: High Risk  
   [*] Total Score: 10  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | Filename   | Rule                                                                      | Confidence | Score | Weight |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | 00001.json | Initialize bitmap object and compress data (e.g. JPEG) into bitmap object | 100%       | 1     | 1.0    |  
   | 00002.json | Open the camera and take picture                                          | 100%       | 1     | 1.0    |  
   | 00003.json | Put the compressed bitmap data into JSON object                           | 80%        | 1     | 0.5    |  
   | 00004.json | Get filename and put it to JSON object                                    | 100%       | 1     | 1.0    |  
   | 00005.json | Get absolute path of file and put it to JSON object                       | 100%       | 1     | 1.0    |  
   | 00006.json | Scheduling recording task                                                 | 80%        | 1     | 0.5    |  
   | 00007.json | Use absolute path of directory for the output media file path             | 100%       | 1     | 1.0    |  
   | 00008.json | Check if successfully sending out SMS                                     | 100%       | 1     | 1.0    |  
   | 00009.json | Put data in cursor to JSON object                                         | 100%       | 1     | 1.0    |  
   | 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON object             | 100%       | 1     | 1.0    |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+


**Assign a role to the agent**

To make Quark Agent's responses more precise and relevant to malware analysis, we assign it the role of an Android malware analysis expert.

.. code-block:: TEXT

   User: 
   As an expert in Android malware analysis, please adjust the values of each rule in the summary report based on my instructions. After each adjustment, update the report and summarize the reason behind the changes as concisely as possible.

.. code-block:: TEXT

   Agent: 
   Certainly! Please provide your instructions for adjusting the values of each rule in the summary report.


**Enhance the summary report**

Then, the agent is ready to enhance the summary report. We then ask it to adjust the scores, weights, and the risk of the sample.

1. Adjust the scores based on the rule descriptions and their combined effects.

.. code-block:: TEXT

   User: 
   Evaluate each rule's threat to sensitive data based on their descriptions and combined effects. Then, adjust each rule's score accordingly. Scores range from 0 to 1, with higher values indicating higher threat.

.. code-block:: TEXT

   Agent: 
   Based on the evaluation of each rule's threat to sensitive data and their combined effects, here are the adjusted scores:

   1. **Initialize bitmap object and compress data (e.g. JPEG) into bitmap object** - Score: 0.6 (Moderate threat; potential for data leakage through images)
   2. **Open the camera and take picture** - Score: 0.9 (High threat; direct access to sensitive data through photos)
   3. **Put the compressed bitmap data into JSON object** - Score: 0.7 (Moderate to high threat; data in JSON can be exploited)
   4. **Get filename and put it to JSON object** - Score: 0.5 (Moderate threat; filenames could lead to sensitive data exposure)
   5. **Get absolute path of file and put it to JSON object** - Score: 0.7 (Moderate to high threat; paths may reveal sensitive data locations)
   6. **Scheduling recording task** - Score: 0.9 (High threat; potential for unauthorized audio recording)
   7. **Use absolute path of directory for the output media file path** - Score: 0.6 (Moderate threat; directory paths could expose sensitive file locations)
   8. **Check if successfully sending out SMS** - Score: 0.8 (High threat; sensitive data can be leaked via SMS)
   9. **Put data in cursor to JSON object** - Score: 0.7 (Moderate to high threat; potentially sensitive data could be exposed)
   10. **Read sensitive data(SMS, CALLLOG) and put it into JSON object** - Score: 1.0 (Critical threat; direct access to sensitive data)

   Now let's update the summary report based on these adjusted scores.  

   
   [!] WARNING: High Risk  
   [*] Total Score: 8.6  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | Filename   | Rule                                                                      | Confidence | Score | Weight |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | 00001.json | Initialize bitmap object and compress data (e.g. JPEG) into bitmap object | 100%       | 0.6   | 1.0    |  
   | 00002.json | Open the camera and take picture                                          | 100%       | 0.9   | 1.0    |  
   | 00003.json | Put the compressed bitmap data into JSON object                           | 80%        | 0.7   | 0.5    |  
   | 00004.json | Get filename and put it to JSON object                                    | 100%       | 0.5   | 1.0    |  
   | 00005.json | Get absolute path of file and put it to JSON object                       | 100%       | 0.7   | 1.0    |  
   | 00006.json | Scheduling recording task                                                 | 80%        | 0.9   | 0.5    |  
   | 00007.json | Use absolute path of directory for the output media file path             | 100%       | 0.6   | 1.0    |  
   | 00008.json | Check if successfully sending out SMS                                     | 100%       | 0.8   | 1.0    |  
   | 00009.json | Put data in cursor to JSON object                                         | 100%       | 0.7   | 1.0    |  
   | 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON object             | 100%       | 1.0   | 1.0    |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+


   **Summary of Changes:**
   - Adjusted scores reflect the potential threat to sensitive data based on the rule descriptions and their implications.
   - High-risk actions such as accessing the camera and reading sensitive data were assigned higher scores, while actions with a lesser impact, such as initializing bitmap objects, were reduced accordingly.
   - The total score is now more representative of the overall risk posed by the application's behavior.


2. Adjust the weights based on the confidence values and their definitions.

.. code-block:: TEXT

   User: 
   Adjust each rule's weight based on the confidence values and the definitions below. Weights range from 0 to 1.

   The definitions of the confidence values:
   - 100%: The sample used all necessary APIs for this behavior, and a related data flow was detected.
   - 80%: The sample used all necessary APIs for this behavior but found no related data flow.
   - 60%: The sample used all necessary APIs for this behavior but in the wrong order.
   - 40%: The sample used only some necessary APIs for this behavior.
   - 20%: The sample did not use the necessary APIs but requested relevant permissions.


.. code-block:: TEXT

   Agent: 
   Based on the provided confidence definitions, here are the adjusted weights for each rule:

   1. **Initialize bitmap object and compress data (e.g. JPEG) into bitmap object** - Weight: 1.0 (100% confidence)
   2. **Open the camera and take picture** - Weight: 1.0 (100% confidence)
   3. **Put the compressed bitmap data into JSON object** - Weight: 0.5 (80% confidence)
   4. **Get filename and put it to JSON object** - Weight: 1.0 (100% confidence)
   5. **Get absolute path of file and put it to JSON object** - Weight: 1.0 (100% confidence)
   6. **Scheduling recording task** - Weight: 0.5 (80% confidence)
   7. **Use absolute path of directory for the output media file path** - Weight: 1.0 (100% confidence)
   8. **Check if successfully sending out SMS** - Weight: 1.0 (100% confidence)
   9. **Put data in cursor to JSON object** - Weight: 1.0 (100% confidence)
   10. **Read sensitive data(SMS, CALLLOG) and put it into JSON object** - Weight: 1.0 (100% confidence)

   Now let's update the summary report based on these adjusted weights.  

   
   [!] WARNING: High Risk  
   [*] Total Score: 8.6  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | Filename   | Rule                                                                      | Confidence | Score | Weight |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | 00001.json | Initialize bitmap object and compress data (e.g. JPEG) into bitmap object | 100%       | 0.6   | 1.0    |  
   | 00002.json | Open the camera and take picture                                          | 100%       | 0.9   | 1.0    |  
   | 00003.json | Put the compressed bitmap data into JSON object                           | 80%        | 0.7   | 0.5    |  
   | 00004.json | Get filename and put it to JSON object                                    | 100%       | 0.5   | 1.0    |  
   | 00005.json | Get absolute path of file and put it to JSON object                       | 100%       | 0.7   | 1.0    |  
   | 00006.json | Scheduling recording task                                                 | 80%        | 0.9   | 0.5    |  
   | 00007.json | Use absolute path of directory for the output media file path             | 100%       | 0.6   | 1.0    |  
   | 00008.json | Check if successfully sending out SMS                                     | 100%       | 0.8   | 1.0    |  
   | 00009.json | Put data in cursor to JSON object                                         | 100%       | 0.7   | 1.0    |  
   | 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON object             | 100%       | 1.0   | 1.0    |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  

   **Summary of Changes:**
   - Adjusted weights reflect the confidence values as per the definitions provided.
   - Rules with 100% confidence retained the highest weight of 1.0, while those with 80% confidence received a weight of 0.5.
   - The total score remains the same, but the weights provide a clearer indication of the reliability of each rule's detection capabilities.


3. Reassess the risk of the sample based on the adjusted scores and weights.

.. code-block:: TEXT
   
   User: 
   Recalculate the total score, reassess the risk of the sample, and explain the reason. Finally, update the report.


.. code-block:: TEXT

   Agent: 
   Based on the recalculated total score of **6.6**, the risk assessment remains categorized as **High Risk**. 

   **Reasoning:**
   - The total score reflects the aggregated threat level based on the adjusted scores and weights. A score of 6.6 indicates a significant potential for sensitive data exposure, especially with key behaviors such as accessing the camera, reading sensitive data, and sending SMS.
   - Despite the adjustments, the presence of high-threat actions maintains the sample's classification as high risk. The analysis indicates that the application has behaviors that could lead to serious privacy violations.

   Let's update the summary report accordingly.

   
   [!] WARNING: High Risk  
   [*] Total Score: 6.6  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | Filename   | Rule                                                                      | Confidence | Score | Weight |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | 00001.json | Initialize bitmap object and compress data (e.g. JPEG) into bitmap object | 100%       | 0.6   | 1.0    |  
   | 00002.json | Open the camera and take picture                                          | 100%       | 0.9   | 1.0    |  
   | 00003.json | Put the compressed bitmap data into JSON object                           | 80%        | 0.7   | 0.5    |  
   | 00004.json | Get filename and put it to JSON object                                    | 100%       | 0.5   | 1.0    |  
   | 00005.json | Get absolute path of file and put it to JSON object                       | 100%       | 0.7   | 1.0    |  
   | 00006.json | Scheduling recording task                                                 | 80%        | 0.9   | 0.5    |  
   | 00007.json | Use absolute path of directory for the output media file path             | 100%       | 0.6   | 1.0    |  
   | 00008.json | Check if successfully sending out SMS                                     | 100%       | 0.8   | 1.0    |  
   | 00009.json | Put data in cursor to JSON object                                         | 100%       | 0.7   | 1.0    |  
   | 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON object             | 100%       | 1.0   | 1.0    |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+


Here is the summary report enhanced by Quark Agent.

.. code-block:: TEXT
   
   [!] WARNING: High Risk  
   [*] Total Score: 6.6  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | Filename   | Rule                                                                      | Confidence | Score | Weight |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+  
   | 00001.json | Initialize bitmap object and compress data (e.g. JPEG) into bitmap object | 100%       | 0.6   | 1.0    |  
   | 00002.json | Open the camera and take picture                                          | 100%       | 0.9   | 1.0    |  
   | 00003.json | Put the compressed bitmap data into JSON object                           | 80%        | 0.7   | 0.5    |  
   | 00004.json | Get filename and put it to JSON object                                    | 100%       | 0.5   | 1.0    |  
   | 00005.json | Get absolute path of file and put it to JSON object                       | 100%       | 0.7   | 1.0    |  
   | 00006.json | Scheduling recording task                                                 | 80%        | 0.9   | 0.5    |  
   | 00007.json | Use absolute path of directory for the output media file path             | 100%       | 0.6   | 1.0    |  
   | 00008.json | Check if successfully sending out SMS                                     | 100%       | 0.8   | 1.0    |  
   | 00009.json | Put data in cursor to JSON object                                         | 100%       | 0.7   | 1.0    |  
   | 00010.json | Read sensitive data(SMS, CALLLOG) and put it into JSON object             | 100%       | 1.0   | 1.0    |  
   +------------+---------------------------------------------------------------------------+------------+-------+--------+

We added the tool ``listDirectory`` to enable Quark Agent access rules in a directory and the tool ``calculateTotalScore`` to recalculate the total score. The entire enhancement of the summary report relies on Quark Agent's understanding of Quark analysis and rules.

.. image:: https://github.com/user-attachments/assets/3e0dd6a3-b31c-4d85-8f92-3f0a2bc9918b

.. note::
   1. The summary report is generated by OpenAI's GPT model and is not always correct.
   2. Since LangChain currently does not support passing Python instances between tools, we temporarily use global variables to pass parameters between tools.
   3. Place the rules and samples in the working directory; the LLM will automatically find the files with matching names.
