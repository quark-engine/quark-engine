++++++++++++++++++++++++++++++++++++++++++++++++++
Quark Script
++++++++++++++++++++++++++++++++++++++++++++++++++

Ecosystem for Mobile Security Tools
------------------------------------

Innovative & Interactive
=========================

The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or **pentest**  the targets.

Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to **interact**  with staged results and perform **creative**  analysis with Quark Script.

Dynamic & Static Analysis
==========================

In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. `objection <https://github.com/sensepost/objection>`_).  

Re-Usable & Sharable
====================

Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges. 

More APIs to come
==================
Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.  

Introduce of Quark Script APIs
------------------------------

Rule(rule.json)
===============

- **Description**: Making detection rule a rule instance
- **params**: Path of a single Quark rule
- **return**: Quark rule instance

runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
===========================================

- **Description**: Given detection rule and target sample, this instance runs the basic Quark analysis.
- **params**: 
    1. Target file 
    2. Quark rule object
- **return**: quarkResult instance

quarkResultInstance.behaviorOccurList
=====================================

- **Description**: List that stores instances of detected behavior in different part of the target file.
- **params**: none
- **return**: detected behavior instance

quarkResultInstance.getAllStrings(none)
=====================================

- **Description**: Get all strings inside the target APK file.
- **params**: none
- **return**: python list containing all strings inside the target APK file.

quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)
==================================================================
- **Description**: Check if target method is in caller method.
- **params**: 
    1. python list contains class name, method name and descriptor of caller method.
    2. python list contains class name, method name and descriptor of target method.
- **return**: True/False

behaviorInstance.firstAPI.fullName
==================================

- **Description**: Show the name of the first key API called in this behavior.
- **params**: none
- **return**: API name

behaviorInstance.secondAPI.fullName
===================================

- **Description**: Show the name of the second key API called in this behavior.
- **params**: none
- **return**: API name

behaviorInstance.hasUrl(none)
=============================

-  **Description**: Check if the behavior contains urls.
-  **params**: none
-  **return**: python list containing all detected urls.

behaviorInstance.methodCaller
=============================

- **Description**: Find method who calls this behavior (API1 & API2).
- **params**: none
- **return**: method instance 

behaviorInstance.getParamValues(none)
=====================================

- **Description**: Get parameter values that API1 sends to API2 in the behavior.
- **params**: none
- **return**: python list containing parameter values.


methodInstance.getXrefFrom(none)
================================

- **Description**: Find out who call this method.
- **params**: none
- **return**: python list containing caller methods.

methodInstance.getXrefTo(none)
==============================

- **Description**: Find out who this method called.
- **params**: none
- **return**: python list containing tuples (callee methods, index).

Objection(host)
===============

- **Description**: Create an instance for Objection (dynamic analysis tool). 
- **params**: Monitoring IP:port
- **return**: objection instance

objInstance.hookMethod(method, watchArgs, watchBacktrace, watchRet)
=====================================================================
- **Description**: Hook the target method with Objection.
- **params**: 
    1. method: the tagrget API. (type: str or method instance) 
    2. watchArgs: Return Args information if True. (type: boolean) 
    3. watchBacktrace: Return backtrace information if True. (type: boolean) 
    4. watchRet: Return the return information of the target API if True (type: boolean).
- **return**: none

Analyzing real case (InstaStealer) using Quark Script
------------------------------------------------------

Quark Script that dynamic hooks the method containing urls 
===========================================================

The scenario is simple! We'd like to dynamic hooking the methods in the malware that contains urls. We can use APIs above to write Quark Script.

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule
    from quark.script.objection import Objection

    SAMPLE_PATH = "6f032.apk"
    RULE_PATH = "00211.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for behaviorInstance in quarkResult.behaviorOccurList:
        detectedUrl = behaviorInstance.hasUrl()
        
        if detectedUrl:
            print(f"\nDetected Behavior -> {ruleInstance.crime}")
            print(f"\nDetected Url -> {detectedUrl}")
            
            method = behaviorInstance.methodCaller
            print(f"\nThe detected behavior was called by -> {method.fullName}")

            print("\nAttempt to hook the method:")
            obj = Objection("127.0.0.1:8888")
            
            obj.hookMethod(method, 
                        watchArgs=True, 
                        watchBacktrace=True, 
                        watchRet=True)
            print(f"\tHook -> {method.fullName}")
            
            for methodCaller in method.getXrefFrom():
                obj.hookMethod(methodCaller, 
                            watchArgs=True, 
                            watchBacktrace=True, 
                            watchRet=True)
                print(f"\tHook -> {methodCaller.fullName}")
                
            for methodCallee, _ in method.getXrefTo():
                obj.hookMethod(methodCallee, 
                            watchArgs=True, 
                            watchBacktrace=True, 
                            watchRet=True)
                print(f"\tHook -> {methodCallee.fullName}")
                
    print("\nSee the hook results in Objection's terminal.")

.. note::
    Please make sure you have the dynamic analysis environment ready before executing the script.

    1. Objection installed and running. Check the guideline `here <https://github.com/sensepost/objection/wiki/Installation>`_.
    2. Android Virtual Machine with frida installed. Check the guideline `here <https://frida.re/docs/android/>`_.
    3. Or a rooted Android Device (Google Pixel 6) with frida installed. Check the root guideline `here <https://forum.xda-developers.com/t/guide-root-pixel-6-with-magisk-android-12-1.4388733/>`_, frida install guideline is the `same <https://frida.re/docs/android/>`_ with Android Virtual Machine.

Quark Script Result
===================

.. image:: https://i.imgur.com/elztZdC.png

Logs on the Objection terminal (hooking)
========================================

.. image:: https://i.imgur.com/XrtfgjY.jpg

Method (callComponentMethod) with urls is detected triggered!
=============================================================

.. image:: https://i.imgur.com/ryV3f57.jpg


Detect CWE-798 in Android Application (ovaa.apk)
------------------------------------------------

This scenario seeks to find hard-coded credentials in the APK file. See `CWE-798 <https://cwe.mitre.org/data/definitions/798.html>`_ for more details.

Let's use this `APK <https://github.com/oversecured/ovaa>`_ and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule ``findSecretKeySpec.json`` to spot on behavior uses method SecretKeySpec. Then, we get all the parameter values that input to this method. From the returned parameter values, we identify it's a AES key and parse the key out of the values. Finally, we dump all strings in the APK file and check if the AES key is in the strings. If the answer is YES, BINGO!!! We find hard-coded credentials in the APK file. 

Quark Scipt: cwe-798.py
========================

.. code-block:: python

    import re
    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "findSecretKeySpec.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for secretKeySpec in quarkResult.behaviorOccurList:
        
        allStrings = quarkResult.getAllStrings()
        
        firstParam = secretKeySpec.getParamValues()[0]
        secondParam = secretKeySpec.getParamValues()[1]
        
        if secondParam == "AES":
            AESKey = re.findall(r'\((.*?)\)', firstParam)[1]
            
        if AESKey in allStrings:
            print(f"Found hard-coded {secondParam} key {AESKey}")


Quark Rule: findSecretKeySpec.json
==================================

.. code-block:: json

    {
        "crime": "Detect APK using SecretKeySpec.",
        "permission": [],
        "api": [
            {
                "descriptor": "()[B",
                "class": "Ljava/lang/String;",
                "method": "getBytes"
            },
            {
                "descriptor": "([BLjava/lang/String;)V",
                "class": "Ljavax/crypto/spec/SecretKeySpec;",
                "method": "<init>"
            }
        ],
        "score": 1,
        "label": []
    }


Quark Script Result
=====================

.. code-block:: TEXT

    $ python3 findSecretKeySpec.py 

    Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f


Hard-Coded AES key in the APK file
===================================

.. code-block:: TEXT

    const-string v2, "49u5gh249gh24985ghf429gh4ch8f23f"

    invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B

    move-result-object v2

    invoke-direct {v1, v2, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V


Detect CWE-94 in Android Application (ovaa.apk)
-----------------------------------------------

This scenario seeks to find code injection in the APK file. See `CWE-94 <https://cwe.mitre.org/data/definitions/94.html>`_ for more details.

Let's use this `APK <https://github.com/oversecured/ovaa>`_ and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule ``loadExternalCode.json`` to spot on behavior uses method createPackageContext. Then, we find the caller method who calls the createPackageContext. Finally, we check if  method checkSignatures is called in the caller method for verification.


Quark Scipt: CWE-94.py
========================

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule
                                                                                                        
    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "loadExternalCode.json"
                                                                                                        
    targetMethod = [
            "Landroid/content/pm/PackageManager;",
            "checkSignatures",
            "(Ljava/lang/String;Ljava/lang/String;)I"
            ]
                                                                                                        
    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
                                                                                                        
    for ldExternalCode in quarkResult.behaviorOccurList:
                                                            
        callerMethod = [
                ldExternalCode.methodCaller.className,
                ldExternalCode.methodCaller.methodName,
                ldExternalCode.methodCaller.descriptor
                ]
                                                                                                        
        if not quarkResult.findMethodInCaller(callerMethod, targetMethod):
            print(f"\nMethod: {targetMethod[1]} not found!")
            print(f"CWE-94 is detected in {SAMPLE_PATH}")

Quark Rule: loadExternalCode.json
==================================

.. code-block:: json
        
    {
        "crime": "Load external code from other APK.",
        "permission": [],
        "api": [
            {
                "descriptor": "(Ljava/lang/String;I)Landroid/content/Context;",
                "class": "",
                "method": "createPackageContext"
            },
            {
                "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;",
                "class": "Ljava/lang/ClassLoader;",
                "method": "loadClass"
            }
        ],
        "score": 1,
        "label": []
    }


Quark Script Result
===================

.. code-block:: TEXT

    $ python3 CWE-94.py

    Method: checkSignatures not found!
    CWE-94 is detected in ovaa.apk
