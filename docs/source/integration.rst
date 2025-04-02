++++++++++++++++++++++++++++++++++++++++
Integration
++++++++++++++++++++++++++++++++++++++++

Quark Engine Integration In Just 2 Steps

First Step: Installation
------------------------

You can install Quark-Engine by following :doc:`the instructions <install>`.

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
                            "class": "Landroid/telephony/TelephonyManager;",
                            "method": "getCellLocation"
                        },
                        {
                            "class": "Landroid/telephony/SmsManager;",
                            "method": "sendTextMessage"
                        }
                    ],
                    "combination": [
                        {
                            "class": "Landroid/telephony/TelephonyManager",
                            "method": "getCellLocation",
                            "descriptor": "()Landroid/telephony/CellLocation;"
                        },
                        {
                            "class": "Landroid/telephony/SmsManager",
                            "method": "sendTextMessage",
                            "descriptor": "(Ljava/lang/String; Ljava/lang/String; Ljava/lang/String; Landroid/app/PendingIntent; Landroid/app/PendingIntent;)V"
                        }
                    ],
                    "sequence": [
                        {
                            "Lcom/google/progress/AndroidClientService; sendMessage ()V": {
                                "first": [
                                    "invoke-virtual",
                                    "v6",
                                    "Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;"
                                ],
                                "first_hex": "6e 10 2f 02 06 00",
                                "second": [
                                    "invoke-virtual",
                                    "v4",
                                    "v6",
                                    "v7",
                                    "Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
                                ],
                                "second_hex": "6e 30 3e 02 64 07"
                            }
                        },
                        {
                            "Lcom/google/progress/AndroidClientService; doByte ([B)V": {
                                "first": [
                                    "invoke-virtual/range",
                                    "v35",
                                    "Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;"
                                ],
                                "first_hex": "74 01 2f 02 23 00",
                                "second": [
                                    "invoke-virtual",
                                    "v0",
                                    "v1",
                                    "v2",
                                    "Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
                                ],
                                "second_hex": "6e 30 3e 02 10 02"
                            }
                        },
                        {
                            "Lcom/google/progress/AndroidClientService$2; run ()V": {
                                "first": [
                                    "invoke-virtual",
                                    "v5",
                                    "Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;"
                                ],
                                "first_hex": "6e 10 2f 02 05 00",
                                "second": [
                                    "invoke-virtual",
                                    "v3",
                                    "v0",
                                    "v4",
                                    "Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
                                ],
                                "second_hex": "6e 30 3e 02 03 04"
                            }
                        }
                    ],
                    "register": [
                        {
                            "Lcom/google/progress/AndroidClientService; sendMessage ()V": {
                                "first": [
                                    "invoke-virtual",
                                    "v6",
                                    "Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;"
                                ],
                                "first_hex": "6e 10 2f 02 06 00",
                                "second": [
                                    "invoke-virtual",
                                    "v4",
                                    "v6",
                                    "v7",
                                    "Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
                                ],
                                "second_hex": "6e 30 3e 02 64 07"
                            }
                        },
                        {
                            "Lcom/google/progress/AndroidClientService$2; run ()V": {
                                "first": [
                                    "invoke-virtual",
                                    "v5",
                                    "Lcom/google/progress/Locate;->getLocation()Ljava/lang/String;"
                                ],
                                "first_hex": "6e 10 2f 02 05 00",
                                "second": [
                                    "invoke-virtual",
                                    "v3",
                                    "v0",
                                    "v4",
                                    "Lcom/google/progress/SMSHelper;->sendSms(Ljava/lang/String; Ljava/lang/String;)I"
                                ],
                                "second_hex": "6e 30 3e 02 03 04"
                            }
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

Radiocontrast
-------------
Radiocontrast is a Quark API that quickly generates Quark rules from a specified method. It builds up 100% matched rules by using native APIs in that method. The feature lets you easily expose the behavior of a method, just like radiocontrast.

For example, we want to know the behavior of a method called `Lahmyth/mine/king/ahmyth/CameraManager;->startUp(I)V,` in Ahmyth.apk.
Here is the simplest way for Radiocontrast usage:

.. code-block:: python

    from quark.radiocontrast import RadioContrast

    # The target APK.
    APK_PATH = "Ahmyth.apk"

    # The method that you want to generate rules. 
    TARGET_METHOD = "Lahmyth/mine/king/ahmyth/CameraManager;->startUp(I)V"

    # The output directory for generated rules.
    GENERATED_RULE_DIR = "~/generated_rules"

    radiocontrast = RadioContrast(
        APK_PATH,
        TARGET_METHOD,
        GENERATED_RULE_DIR
    )
    radiocontrast.rule_generate()
