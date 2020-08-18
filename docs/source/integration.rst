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

    >>> from quark.Objects.quark import Quark
    >>> from quark.Objects.quarkrule import QuarkRule

    2. Examine apk with one single rule::

    >>> apk_path = "14d9f1a92dd984d6040cc41ed06e273e.apk"
    >>> quark = Quark(apk_path)

    >>> rule_path = "sendContact_SMS.json"
    >>> rule_object = QuarkRule(rule_path)

    >>> quark.run(rule_object)

    3. Three ways for report to present

    Show summary report::

        >>> quark.show_summary_report(rule_object)
        >>> print(quark.tb)

    .. code-block::

        +----------------------+------------+-------+--------+
        | Rule                 | Confidence | Score | Weight |
        +----------------------+------------+-------+--------+
        | Send contact via SMS | 100%       | 2     | 2.0    |
        +----------------------+------------+-------+--------+

    Show detail report::

        >>> quark.show_detail_report(rule_object)

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

        >>> quark.generate_json_report(rule_object)
        >>> report = quark.get_json_report()

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
Example
#########
Here give an example for module usage
    .. code-block:: python

        import json

        from quark.Objects.quark import Quark
        from quark.Objects.quarkrule import QuarkRule

        apk_path = "14d9f1a92dd984d6040cc41ed06e273e.apk"
        quark = Quark(apk_path)

        rule_path = "sendContact_SMS.json"
        rule_object = QuarkRule(rule_path)

        quark.run(rule_object)

        # Generate summary reporte
        quark.show_summary_report(rule_object)
        # Print detail report
        quark.show_detail_report(rule_object)
        # Generate json report
        quark.generate_json_report(rule_object)

        # Print summary report table
        print(quark.tb)
        # Print Json report
        print(json.dumps(quark.get_json_report(), indent=4))