++++++++++++++++++++++++++++++++++++++++
Rule Generation
++++++++++++++++++++++++++++++++++++++++

The Rule generation technique is based on the idea below:

1. Sort all APIs used in an APK by their usage counts.
2. Separate all APIs into two groups, P(20% least usage count) and S(other 80% APIs), by the Pareto principle (20-80 rule)
3. Combine $P$ and $S$ into four different phases:
    - PxP
    - PxS 
    - SxP 
    - SxS
4. Execute the rule generation with each phase in this order: PxP -> PxS -> SxP -> SxS

The earlier the phase, the higher the value of the rule but less time spent.
We can generate rules in a phased manner according to different situations.
For example, under a time constraint, we can take PxP phase rules as an overview for the target APK.

CLI Usage
------------------------
Generate rules for APK with the following command::

    $ quark -a <sample path> --generate-rule <generated rule directory path>

Generate rules and web editor with the following command::

    $ quark -a <sample path> --generate-rule <generated rule directory path> -w <web editor file name>


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
You can easily review and edit generated rules with 5 steps:

1. Input keywords to search rules.
2. Select the generated rules you want to save.
3. Edit rule information.

.. image:: https://i.imgur.com/0FLlGq0.png

4. Edit crime, score, and labels with the editor.
5. Save the edited rule.

.. image:: https://i.imgur.com/kIVIeCk.png