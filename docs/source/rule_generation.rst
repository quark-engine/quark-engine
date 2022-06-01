++++++++++++++++++++++++++++++++++++++++
Rule Generation
++++++++++++++++++++++++++++++++++++++++

The Rule generation technique is based on the folowing idea belows:

1. Sort API by API usage count
2. Separate all API into two groups, P(20% least usage count) and S(other 80% API), by the Pareto principle (20-80 rule)
3. Combine $P$ and $S$ into four different phases:
    - PxP
    - PxS 
    - SxP 
    - SxS
4. Execute rule generate by phase: PxP -> PxS -> SxP -> SxS

The earlier the phase, the higher the value of the rule but less time spent.
We can generate rules in a phased manner according to different situations.
For example, under a time constraint, we can take PxP phase rules as an overview for the target APK.

CLI Usage
------------------------
Generate rules for apk with the following command::

    $ Quark -a <sample path> --generate-rule <generated rule directory path>

Generate rules and web editor with the following command::

    $ Quark -a <sample path> --generate-rule <generated rule directory path> -w <report file path>


API Usage
-----------------------------------

And here is the simplest way for API usage:

.. code-block:: python

    from quark.rulegeneration import RuleGeneration

   # The target APK.
    APK_PATH = "Ahmyth.apk"

    # The output directory for generated rules.
    GENERATED_RULE_DIR = "generated_rules"

    generator = RuleGeneration(APK_PATH, GENERATED_RULE_DIR)
    generator.generate_rule(web_editor="report.html")


Web Editor Tutorial
-----------------------------------

Here is the demo for the rule generation web editor.
You can easily review and edit generated rules with 4 steps:

1. Input keywords to search rules.
2. Select the generated rules you want to save.
3. Edit rule information.

.. image:: https://i.imgur.com/0FLlGq0.png

4. Edit crime, score, and labels with the editor.
5. Save the edited rule.

.. image:: https://i.imgur.com/kIVIeCk.png