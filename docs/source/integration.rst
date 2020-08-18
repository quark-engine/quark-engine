+++++++++++
Integration
+++++++++++

--------------------------
Quark-Engine usage example
--------------------------

This is the guidance for using quark-engine as a Python module
    
Install
#########
::

    $ pip3 install quark-engine

Implement
#########

    1. import module::

    >>> from quark.Objects.xrule import XRule
    >>> from quark.Objects.ruleobject import RuleObject

    2. Examine apk with one single rule::

    >>> apk_path = "quark/sample/14d9f1a92dd984d6040cc41ed06e273e.apk"
    >>> data = XRule(apk_path)

    >>> rule_path = "quark/rules/sendContact_SMS.json"
    >>> rule_object = RuleObject(rule_path)

    >>> data.run(rule_object)

    3. Three ways for report to present

    Show summary report::

        >>> data.show_summary_report(rule_object)
        >>> print(data.tb)

    .. code-block::

        +----------------------+------------+-------+--------+
        | Rule                 | Confidence | Score | Weight |
        +----------------------+------------+-------+--------+
        | Send contact via SMS | 100%       | 2     | 2.0    |
        +----------------------+------------+-------+--------+

    Show detail report::

        >>> data.show_detail_report(rule_object)

    .. code-block::

        Confidence: 100%

            [✓]1.Permission Request
                android.permission.SEND_SMS
                android.permission.READ_CONTACTS
            [✓]2.Native API Usage
                (Landroid/content/ContentResolver, query)
                (Landroid/telephony/SmsManager, sendTextMessage)
            [✓]3.Native API Combination
                (Landroid/content/ContentResolver, query)
                (Landroid/telephony/SmsManager, sendTextMessage)
            [✓]4.Native API Sequence
                Sequence show up in:
                (Lcom/google/progress/AndroidClientService;, sendMessage)
                (Lcom/google/progress/AndroidClientService;, doByte)
            [✓]5.Native API Use Same Parameter
                (Lcom/google/progress/AndroidClientService;, sendMessage)

    Show json report::

        >>> data.show_json_report(rule_object)
        >>> report = data.get_json_report()

        >>> import json
        >>> print(json.dumps(report, indent=4))

    .. code-block:: json

        {
            "md5": "14d9f1a92dd984d6040cc41ed06e273e",
            "apk_filename": "14d9f1a92dd984d6040cc41ed06e273e.apk",
            "size_bytes": 166917,
            "threat_level": "High Risk",
            "total_score": 4,
            "crimes": [
                {
                    "crime": "Send Location via SMS",
                    "score": 4,
                    "weight": 4.0,
                    "confidence": "100%",
                    "permissions": [
                        "android.permission.SEND_SMS",
                        "android.permission.ACCESS_COARSE_LOCATION",
                        "android.permission.ACCESS_FINE_LOCATION"
                    ],
                    "api": [
                        {
                            "class": "Landroid/telephony/TelephonyManager",
                            "method": "getCellLocation"
                        },
                        {
                            "class": "Landroid/telephony/SmsManager",
                            "method": "sendTextMessage"
                        }
                    ],
                    "combination": [
                        {
                            "class": "Landroid/telephony/TelephonyManager",
                            "method": "getCellLocation"
                        },
                        {
                            "class": "Landroid/telephony/SmsManager",
                            "method": "sendTextMessage"
                        }
                    ],
                    "sequence": [
                        {
                            "class": "Lcom/google/progress/AndroidClientService;",
                            "method": "doByte"
                        },
                        {
                            "class": "Lcom/google/progress/AndroidClientService;",
                            "method": "sendMessage"
                        }
                    ],
                    "register": [
                        {
                            "class": "Lcom/google/progress/AndroidClientService;",
                            "method": "sendMessage"
                        }
                    ]
                }
            ]
        }
