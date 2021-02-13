++++++++++++++++++++++++++++++++++++++++
Integration
++++++++++++++++++++++++++++++++++++++++

Quark Engine Integration In Just 2 Steps

First Step: Installation
------------------------

::

    $ pip3 install quark-engine

Second Step: Code Snippet As You Go
-----------------------------------

Here we present the simplest way for quark API usage:

.. code-block:: python

    from quark.report import Report

    APK_PATH = "14d9f1a92dd984d6040cc41ed06e273e.apk"
    RULE_PATH = "sendLocation_SMS.json"

    report = Report()

    '''
    RULE_PATH can be a directory with multiple rules inside
    EX: "rules/"
    '''
    report.analysis(APK_PATH, RULE_PATH)
    json_report = report.get_report("json")
    print(json_report)


Then you get the json report. :D

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
                    "native_api": [
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

.. _dir_scan:

Directory Scanning
------------------

To scan the entire directory with quark, you can use a simple bash script.

.. code-block:: bash

    #!/bin/bash
    for apkFile in *.apk; do
        quark -a ${apkFile} -o ${apkFile%%.*}_output.json;
    done;

Alternatively, you can use the quark API as well.

.. code-block:: python

    #!/usr/bin/env python
    from glob import glob

    from quark.report import Report

    RULE_PATH = "./quark-rules/00001.json"

    report = Report()

    for file in glob('*.apk'): 
        report.analysis(file, RULE_PATH)
        json_report = report.get_report("json")
        print(json_report)
