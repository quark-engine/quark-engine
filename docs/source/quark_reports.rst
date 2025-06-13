++++++++++++++++++++++++++++++++++++++++
Quark Report
++++++++++++++++++++++++++++++++++++++++

Easy to Use and Intuitive Report
---------------------------------------

Quark provides **7 flexible report formats** to boost your analysis.

* `Summary Report`_
* `Detail Report`_
* `Web Report`_
* `Label-based Report`_
* `Behaviors Comparison Radar Chart`_
* `Call Graph`_
* `Rule Classification`_

Please see below for more details.

 .. _summary-report:

Summary Report
--------------

Examine with rules.

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s

There is the possibility to select only one label to filter the rules:

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s network


There is also the possibility to select only one rule:

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s <path_to_the_rule>


.. image:: https://i.imgur.com/v7ehRW0.png

Note that if you want to select the default rules of Quark, the path to the ruleset is ``$HOME/.quark-engine/quark-rules/rules/``.

Detail Report
-------------

This is how we examine a real android malware (candy corn) with one single rule (crime).

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d


There is the possibility to select only one label to filter the rules:

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d network


There is also the possibility to select only one rule:

.. code-block:: bash

    quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d <path_to_the_rule>

.. image:: https://i.imgur.com/LFLFpvc.png

Note that if you want to select the default rules of Quark, the path to the ruleset is ``$HOME/.quark-engine/quark-rules/rules/``.

Web Report
----------------

With the following command, you can easily analyze the Android sample and output the web report. See our demo `here <https://pulorsok.github.io/ruleviewer/web-report-demo>`_.

.. code-block:: python

    quark -a sample.apk -s -w quark_report.html


.. image:: https://i.imgur.com/fNc3mC0.jpg

Label-based Report
------------------

Check which topic (indicated by `labels <https://github.com/quark-engine/quark-rules/blob/master/label_desc.csv>`_) of the malware is more aggressive.

.. code-block:: bash

    quark -a Ahmyth.apk -l detailed

.. image:: https://i.imgur.com/0GbBDfn.png

Behaviors Comparison Radar Chart
--------------------------------

With the following command, you can compare different APK actions based on the max confidence of rule labels and generate a radar chart.

.. code-block:: bash

    quark -a first.apk -a second.apk -C

.. image:: https://i.imgur.com/ClRWOei.png

Call Graph
----------

You can add the ``-g`` option to the quark command, and you can get the call graph (only those rules match with 100% confidence).

.. code-block:: bash

    quark -a Ahmyth.apk -s -g

.. image:: https://i.imgur.com/5xcrcdN.png

.. _rule-classification:

Rule Classification
--------------------

You can add the ``-c`` option to the quark command, and you can output the rules classification with the mutual parent function (only those rules match with 100% confidence).

.. code-block:: bash

    quark -a Ahmyth.apk -s -c

.. image:: https://i.imgur.com/YTK8V1x.png

