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
    1. SAMPLE_PATH: Target file 
    2. ruleInstance: Quark rule object
- **return**: quarkResult instance

quarkResultInstance.behaviorOccurList
=====================================

- **Description**: List that stores instances of detected behavior in different part of the target file.
- **params**: none
- **return**: detected behavior instance

quarkResultInstance.getAllStrings(none)
=======================================

- **Description**: Get all strings inside the target APK file.
- **params**: none
- **return**: python list containing all strings inside the target APK file.

quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)
==================================================================
- **Description**: Check if target method is in caller method.
- **params**: 
    1. callerMethod: python list contains class name, method name and descriptor of caller method.
    2. targetMethod: python list contains class name, method name and descriptor of target method.
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

behaviorInstance.isArgFromMethod(targetMethod)
==============================================

- **Description**: Check if there are any arguments from the target method.
- **params**: 
    1. targetMethod: python list contains class name, method name, and descriptor of target method
- **return**: True/False

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

methodInstance.getArguments(none)
==============================

- **Description**: Get arguments from method.
- **params**: none
- **return**: python list containing arguments.

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
    4. watchRet: Return the return information of the target API if True. (type: boolean)
- **return**: none

runFridaHook(apkPackageName, targetMethod, methodParamTypes, secondToWait)
============================================================================

- **Description**: Track calls to the specified method for given seconds.
- **params**:
    1. apkPackageName: the package name of the target APP
    2. targetMethod: the target API
    3. methodParamTypes: string that holds the parameters used by the target API
    4. secondToWait: seconds to wait for method calls, defaults to 10
- **return**: FridaResult instance

checkClearText(inputString)
============================

- **Description**: Check the decrypted value of the input string.
- **params**:
    1. inputString: string to be checked
- **return**: the decrypted value

getActivities(samplePath)
==========================
- **Description**: Get activities from the manifest of target sample.
- **params**: 
    1. samplePath: the file path of target sample
- **return**: python list containing activities

activityInstance.hasIntentFilter(none)
======================================
- **Description**: Check if the activity has an intent-filter.
- **params**: none
- **return**: True/False

activityInstance.isExported(none)
==================================
- **Description**: Check if the activity set ``android:exported=true``.
- **params**: none
- **return**: True/False


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

Quark Scipt: CWE-798.py
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


Detect CWE-921 in Android Application (ovaa.apk)
------------------------------------------------

This scenario seeks to find unsecure storage mechanism of data in the APK file. See `CWE-921 <https://cwe.mitre.org/data/definitions/921.html>`_ for more details.

Let's use this `APK <https://github.com/oversecured/ovaa>`_ and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule ``checkFileExistence.json`` to spot on behavior that checks if a file exist on given storage mechanism. Then, we use API ``getParamValues()`` to get the file path. Finally, CWE-921 is found if the file path contains keyword ``sdcard``.

Quark Script CWE-921.py
========================

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "ovaa.apk"
    RULE_PATH = "checkFileExistence.json"

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for existingFile in quarkResult.behaviorOccurList:
        filePath = existingFile.getParamValues()[0]
        if "sdcard" in filePath:
            print(f"This file is stored inside the SDcard\n")
            print(f"CWE-921 is detected in {SAMPLE_PATH}.")

Quark Rule: checkFileExistence.json
===================================

.. code-block:: json

    {
        "crime": "Check file existence",
        "permission": [],
        "api": [
            {
                "descriptor": "(Ljava/lang/String;)V",
                "class": "Ljava/io/File;",
                "method": "<init>"
            },
            {
                "descriptor": "()Z",
                "class": "Ljava/io/File;",
                "method": "exists"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-921.py 
    This file is stored inside the SDcard

    CWE-921 is detected in ovaa.apk.


Detect CWE-312 in Android Application (ovaa.apk)
------------------------------------------------

This scenario seeks to find cleartext storage of sensitive data in the APK file. See `CWE-312 <https://cwe.mitre.org/data/definitions/312.html>`_ for more details.

Let's use this `APK <https://github.com/oversecured/ovaa>`_ and the above APIs to show how Quark script find this vulnerability.

First, we designed a `Frida <https://frida.re>`_ script ``agent.js`` to hook the target method and get the arguments when the target method is called. Then we hook the method ``putString`` to catch its arguments. Finally, we use `Ciphey <https://github.com/Ciphey/Ciphey>`_ to check if the arguments are encrypted.

Quark Script CWE-312.py
========================

.. code-block:: python

    from quark.script.frida import runFridaHook
    from quark.script.ciphey import checkClearText

    APP_PACKAGE_NAME = "oversecured.ovaa"

    TARGET_METHOD = "android.app." \
                    "SharedPreferencesImpl$EditorImpl." \
                    "putString"

    METHOD_PARAM_TYPE = "java.lang.String," \
                        "java.lang.String"

    fridaResult = runFridaHook(APP_PACKAGE_NAME,
                                TARGET_METHOD,
                                METHOD_PARAM_TYPE,
                            secondToWait = 10)

    for putString in fridaResult.behaviorOccurList:

        firstParam, secondParam = putString.getParamValues()

        if firstParam in ["email", "password"] and \
            secondParam == checkClearText(secondParam):
            
            print(f'The CWE-312 vulnerability is found. The cleartext is "{secondParam}"')

Frida Script: agent.js
=======================

.. code-block:: javascript

    // -*- coding: utf-8 -*-
    // This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
    // See the file 'LICENSE' for copying permission.

    /*global Java, send, rpc*/
    function replaceMethodImplementation(targetMethod, classAndMethodName, methodParamTypes, returnType) {
        targetMethod.implementation = function () {
            let callEvent = {
                "type": "CallCaptured",
                "identifier": [classAndMethodName, methodParamTypes, returnType],
                "paramValues": []
            };

            for (const arg of arguments) {
                callEvent["paramValues"].push((arg || "(none)").toString());
            }

            send(JSON.stringify(callEvent));
            return targetMethod.apply(this, arguments);
        };
    }

    function watchMethodCall(classAndMethodName, methodParamTypes) {
        if (classAndMethodName == null || methodParamTypes == null) {
            return;
        }

        const indexOfLastSeparator = classAndMethodName.lastIndexOf(".");
        const classNamePattern = classAndMethodName.substring(0, indexOfLastSeparator);
        const methodNamePattern = classAndMethodName.substring(indexOfLastSeparator + 1);

        Java.perform(() => {
            const classOfTargetMethod = Java.use(classNamePattern);
            const possibleMethods = classOfTargetMethod[`${methodNamePattern}`];

            if (typeof possibleMethods === "undefined") {
                const failedToWatchEvent = {
                    "type": "FailedToWatch",
                    "identifier": [classAndMethodName, methodParamTypes]
                };

                send(JSON.stringify(failedToWatchEvent));
                return;
            }

            possibleMethods.overloads.filter((possibleMethod) => {
                const paramTypesOfPossibleMethod = possibleMethod.argumentTypes.map((argument) => argument.className);
                return paramTypesOfPossibleMethod.join(",") === methodParamTypes;
            }).forEach((matchedMethod) => {
                const retType = matchedMethod.returnType.name;
                replaceMethodImplementation(matchedMethod, classAndMethodName, methodParamTypes, retType);
            }
            );

        });
    }

    rpc.exports["watchMethodCall"] = (classAndMethodName, methodParamTypes) => watchMethodCall(classAndMethodName, methodParamTypes);

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-312.py
    The CWE-312 vulnerability is found. The cleartext is "test@email.com"
    The CWE-312 vulnerability is found. The cleartext is "password"

Detect CWE-89 in Android Application (AndroGoat.apk)
----------------------------------------------------

This scenario seeks to find SQL injection in the APK file. See `CWE-89 <https://cwe.mitre.org/data/definitions/89.html>`_ for more details.

Let's use this `APK <https://github.com/satishpatnayak/AndroGoat>`_ and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule ``executeSQLCommand.json`` to spot on behavior using SQL command Execution. Then, we use API ``isArgFromMethod`` to check if ``append`` use the value of ``getText`` as the argument. If yes, we confirmed that the SQL command string is built from user input, which will cause CWE-89 vulnerability.

Quark Script CWE-89.py
======================

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "AndroGoat.apk"
    RULE_PATH = "executeSQLCommand.json"

    targetMethod = [
        "Landroid/widget/EditText;", # class name 
        "getText",                   # method name
        "()Landroid/text/Editable;", # descriptor
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for sqlCommandExecution in quarkResult.behaviorOccurList:
        if sqlCommandExecution.isArgFromMethod(
            targetMethod
        ):
            print(f"CWE-89 is detected in {SAMPLE_PATH}")

Quark Rule: executeSQLCommand.json
==================================

.. code-block:: json

    {
        "crime": "Execute SQL Command",
        "permission": [],
        "api": [
            {
                "class": "Ljava/lang/StringBuilder;",
                "method": "append",
                "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
            },
            {
                "class": "Landroid/database/sqlite/SQLiteDatabase;",
                "method": "rawQuery",
                "descriptor": "(Ljava/lang/String; [Ljava/lang/String;)Landroid/database/Cursor;"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-89.py

    CWE-89 is detected in AndroGoat.apk


Detect CWE-926 in Android Application (dvba.apk)
----------------------------------------------------

This scenario seeks to find **improper export of Android application components** in the APK file. See `CWE-926 <https://cwe.mitre.org/data/definitions/926.html>`_ for more details.

Let's use this `APK <https://github.com/rewanthtammana/Damn-Vulnerable-Bank>`_ and the above APIs to show how Quark script find this vulnerability.

First, we use Quark API ``getActivities`` to get all activity data in the manifest. Then we use ``activityInstance.hasIntentFilter`` to check if the activities have ``intent-filter``. Also, we use ``activityInstance.isExported`` to check if the activities set the attribute ``android:exported=true``. If both are **true**, then the APK exports the component for use by other applications. That may cause CWE-926 vulnerabilities.

Quark Script CWE-926.py
=======================

.. code-block:: python

    from quark.script import *

    SAMPLE_PATH = "dvba.apk"

    for activityInstance in getActivities(SAMPLE_PATH):
        
        if activityInstance.hasIntentFilter() and activityInstance.isExported():
            print(f"CWE-926 is detected in the activity, {activityInstance}")

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-926.py

    CWE-926 is found in the activity, com.app.damnvulnerablebank.CurrencyRates
    CWE-926 is found in the activity, com.app.damnvulnerablebank.SplashScreen

Detect CWE-749 in Android Application (MSTG-Android-Java.apk)
-------------------------------------------------------------

This scenario seeks to find **exposed methods or functions** in the APK file. See `CWE-749 <https://cwe.mitre.org/data/definitions/749.html>`_ for more details.

Let's use this `APK <https://github.com/OWASP/MASTG-Hacking-Playground>`_ and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule ``configureJsExecution.json`` to spot on behavior using method ``setJavascriptEnabled``. Then, we use API ``methodInstance.isArgumentTrue`` to check if it enables JavaScript execution on websites. Finally, we look for calls to method ``addJavaScriptInterface`` in the caller method. If **yes**, the APK exposes methods or functions to websites. That causes CWE-749 vulnerability.

Quark Script CWE-749.py
=======================

.. code-block:: python

    from quark.script import runQuarkAnalysis, Rule

    SAMPLE_PATH = "MSTG-Android-Java.apk"
    RULE_PATH = "configureJsExecution.json"

    targetMethod = [
        "Landroid/webkit/WebView;",
        "addJavascriptInterface",
        "(Ljava/lang/Object; Ljava/lang/String;)V"
    ]

    ruleInstance = Rule(RULE_PATH)
    quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

    for configureJsExecution in quarkResult.behaviorOccurList:

        caller = configureJsExecution.methodCaller
        secondAPI = configureJsExecution.secondAPI

        enableJS = secondAPI.getArguments()[1]
        exposeAPI = quarkResult.findMethodInCaller(caller, targetMethod)

        if enableJS and exposeAPI:
            print(f"CWE-749 is detected in method, {caller.fullName}"

configureJsExecution.json
=========================

.. code-block:: json
    {
        "crime": "Configure JavaScript execution on websites",
        "permission": [],
        "api": [
            {
                "class": "Landroid/webkit/WebView;",
                "method": "getSettings",
                "descriptor": "()Landroid/webkit/WebSettings;"
            },
            {
                "class": "Landroid/webkit/WebSettings;",
                "method": "setJavaScriptEnabled",
                "descriptor": "(Z)V"
            }
        ],
        "score": 1,
        "label": []
    }

Quark Script Result
====================

.. code-block:: TEXT

    $ python3 CWE-749.py

    CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Remote; onCreate (Landroid/os/Bundle;)V
    CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Local; onCreate (Landroid/os/Bundle;)V
