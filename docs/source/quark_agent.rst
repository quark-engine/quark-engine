Quark Agent
===========

Introducing Quark's new member, the Quark Agent, the second AI assistant in the Quark team. This agent lets users get Quark reports using natural language, eliminating the need for terminal commands and making the analysis simple and user-friendly.

The Quark Agent integrates with LangChain, using OpenAI's large language model to act as a bridge between the natural language and the Quark APIs. LangChain defines the Quark APIs as tools that large language models can understand and use. This means users can run any Quark analysis using natural language by simply adding new tools as needed.

Showcase: Generate Summary Report with Quark Agent
--------------------------------------------------

Here's an example of using the Quark Agent. This agent can currently analyze `ovaa.apk <https://github.com/oversecured/ovaa>`__ and generate a :ref:`summary report <summary-report>`. See the details below.

Quick Start
~~~~~~~~~~~

1. Install the Quark Agent:

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

4. Run the Quark Agent:

   .. code-block:: shell

      quark-agent

5. Result:

.. image:: https://github.com/user-attachments/assets/46407664-de0d-4849-8995-642ff636d71e


Decode the Prompts
~~~~~~~~~~~~~~~~~~

Here, we explain what happens after running the Quark Agent.

**Preset Prompt**

To ensure the ``gpt-4o-mini`` model follows the correct format of a summary report, we designed the following preset prompt and hard-coded it into the Quark Agent.

When the Quark Agent starts, it will automatically pass the preset prompt to the ``gpt-4o-mini`` model. Hence, we don't need to pass this prompt manually.

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

Then, by passing the following prompt manually, we ask the Quark Agent to analyze the `ovaa.apk <https://github.com/oversecured/ovaa>`__ sample and generate a summary report. 

.. code:: TEXT

   1st Prompt: Analyze the sample “ovaa.apk” using Quark and the rule “constructCryptoGraphicKey.json.”
               After the analysis, print the summary report.

Used Quark APIs/Tools that LLM used: ``initRuleObject``, ``initQuarkObject``, ``runQuarkAnalysisForSummaryReport``, ``getSummaryReportTable``, ``getAnalysisResultRisk``, and ``getAnalysisResultScore``

To highlight the analysis result, we ask the Quark Agent to colorize the summary report.

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

Now, let's explain what happens after running the Quark Agent.

**Generate a summary report**

We ask the Quark Agent to generate a summary report for `Ahmyth.apk <https://github.com/quark-engine/apk-samples/blob/master/malware-samples/Ahmyth.apk>`__ .

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

To make the Quark Agent's responses more precise and relevant to malware analysis, we assign it the role of an Android malware analysis expert.

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


Here is the summary report enhanced by the Quark Agent.

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

We added the tool ``listDirectory`` to enable the Quark Agent access rules in a directory and the tool ``calculateTotalScore`` to recalculate the total score. The entire enhancement of the summary report relies on the Quark Agent's understanding of Quark analysis and rules.

.. image:: https://github.com/user-attachments/assets/3e0dd6a3-b31c-4d85-8f92-3f0a2bc9918b

.. note::
   1. The summary report is generated by OpenAI's GPT model and is not always correct.
   2. Since LangChain currently does not support passing Python instances between tools, we temporarily use global variables to pass parameters between tools.
   3. Place the rules and samples in the working directory; the LLM will automatically find the files with matching names.
