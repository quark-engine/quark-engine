=====================
Quark-Engine Workflow
=====================

.. image:: https://i.imgur.com/xN4js5P.png



Quark-Engine Step 1(Command Line)
=================================

``quark.cli`` is the entry point of the program, and it will initialize the ``XRule``
object and the ``RuleObject`` object according to the given APK file
and JSON rules, and create ``quark.utils.weight`` object at the end to
calculate the weighted score, finally, display the report according to ``-s``
or ``-d``. No matter whether you choose the detail report or the summary
report, a full analysis will be run. The difference is that the report display
is different.

.. image:: https://i.imgur.com/QZOMJSY.png

Quark-Engine through the command interface to execute malware analysis like below:

Summary Report::

    $ quark -a malware.apk -r rule -s

Detail Report::

    $ quark -a malware.apk -r rule -d


The Quark-Engine will start from the ``quark.cli`` module, which is our first step in the above image.

.. code-block::

    -a specifies an apk file
    -r will specify a rule directory
    -s for summary report
    -d for detail report




Quark-Engine Step 2 (APK Information Extract)
=============================================

In step 2, we will extract the information we want from the given APK file,
such as the permission request list, what native APIs are called, and with the
help of androguard, we can find the cross-reference method from the given
function name, and also get the Dalvik bytecode instruction.




Quark-Engine Step 3 (Load JSON Rule)
====================================

In step 3, we will traverse each JSON file from the rules folder given by ``-r``
in the command-line interface, and each JSON file will be considered a five-stage
rule of malicious behavior.




Quark-Engine Step 4 (Level 1-5 Check)
=====================================

In step 4, We will follow our custom five-stage crime rules, which are as follows:

1. Permission requested.
2. Native API call.
3. Certain combination of native API.
4. Calling sequence of native API.
5. APIs that handle the same register.

Detailed implementation principle, please refer to the ``quark.Objects.xrule``.




Quark-Engine Step 5 (Weighted Score Calculation)
================================================

In step 5, We will calculate the weighted score of each five-stage crime rule
based on the stages we found by each rule, and sum up each score. Further, we
will have a set of formulas to evaluate which risk range this weighted score
is, such as ``low risk``, ``medium risk``, and ``high risk``.

First of all, in each of the five-stage crime rules, there is a field called
yscore. This score is based on the severity of the crime.

Take this rule for example:

.. code-block::

    {
        "crime": "Send Location via SMS",
        "x1_permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION"
        ],
        "x2n3n4_comb": [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation"
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage"
            }
        ],
        "yscore": 4
    }

As you can see, this rule has a field called ``yscore``, which is ``4``.
Then, after the ``RuleObject`` initialize this rule, you can get this score by
using ``RuleObject.yscore``.

After that, while the five-stage analysis check is completed, we can know which
crime stages have been reached. We will use get_score to get the weighted score
of this five-stage crime rule.

.. code-block::

    def get_score(self, confidence):
        """
        According to the state of the five stages, we calculate the weighted score based on exponential growth.
        For example, we captured the third stage in five stages, then the weighted score would be (2^3-1) / 2^4.

        2^(confidence - 1)

        :param confidence:
        :return: floating point
        """
        if confidence == 0:
            return 0
        return (2 ** (confidence - 1) * self._yscore) / 2 ** 4

So assuming this rule, we captured the ``fourth stage``, that is, we can confirm
that the two native APIs appear in order. Then the calculation of this score
is (2 ** (``4`` - 1) * self._yscore) / 2 ** 4, which is ``2``.

As for our risk range is defined in function ``calculate`` of ``qaurk.utils.weight``.

There are five level threshold, the range are defined as below:

.. code-block::

    # Level 1 threshold
    level_one_threshold = self.score_sum / 2 ** 4

    # Level 2 threshold
    level_two_threshold = self.score_sum / 2 ** 3

    # Level 3 threshold
    level_three_threshold = self.score_sum / 2 ** 2

    # Level 4 threshold
    level_four_threshold = self.score_sum / 2 ** 1

    # Level 5 threshold
    level_five_threshold = self.score_sum / 2 ** 0

If the final total risk score falls in the ``first and second`` stages, it is **low
risk**; if it is in the ``third and fourth`` stages, it is **medium risk**. If it is in
the ``fifth`` stage, it is **high risk**.




Quark-Engine Step 6 (Report)
============================

As a final step, we present our analysis report in two forms, a summary report
and a detailed report.

Summary Report
--------------

.. image:: https://i.imgur.com/Ib01V6k.png

Detail Report
---------------

.. image:: https://i.imgur.com/kh1jpsQ.png