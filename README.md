<p align="center">
    <a href="https://www.blackhat.com/asia-21/arsenal/schedule/index.html#quark-engine-storyteller-of-android-malware-22458">
        <img alt="Black Hat Arsenal" src="https://img.shields.io/badge/Black%20Hat%20Arsenal-Asia%202021-blue">
    </a>
    <a href="https://conference.hitb.org/hitb-lockdown002/sessions/quark-engine-an-obfuscation-neglect-android-malware-scoring-system/">
        <img alt="HITB" src="https://img.shields.io/badge/HITB-Lockdown%20002-red">
    </a>
    <a href="https://www.youtube.com/watch?v=SOH4eqrv9_g&ab_channel=ROOTCONHackingConference">
        <img alt="rootcon" src="https://img.shields.io/badge/ROOTCON-2020-orange">
    </a>
    <a href="https://www.youtube.com/watch?v=XK-yqHPnsvc&ab_channel=DEFCONConference">
        <img alt="defcon" src="https://img.shields.io/badge/DEFCON%2028-BTV-blue">
    </a><br>
    <a href="https://github.com/quark-engine/quark-engine/actions/workflows/pytest.yml">
        <img alt="build status" src="https://github.com/quark-engine/quark-engine/actions/workflows/pytest.yml/badge.svg">
    </a>
    <a href="https://codecov.io/gh/quark-engine/quark-engine">
        <img alt="codecov" src="https://codecov.io/gh/quark-engine/quark-engine/branch/master/graph/badge.svg">
    </a>
    <a href="https://github.com/18z/quark-rules/blob/master/LICENSE">
        <img alt="license" src="https://img.shields.io/badge/License-GPLv3-blue.svg">
    </a>
    <a href="https://www.python.org/downloads/release/python-360/">
        <img alt="python version" src="https://img.shields.io/badge/python-3.8-blue.svg">
    </a>
    <a href="https://pypi.org/project/quark-engine/">
        <img alt="PyPi Download" src="https://pepy.tech/badge/quark-engine">
    </a><br>
    <a href="https://twitter.com/quarkengine">
        <img alt="Twitter" src="https://img.shields.io/twitter/follow/quarkengine?style=social">
    </a><br>
    <b> An Obfuscation-Neglect Android Malware Scoring System</b>
    <img src="https://i.imgur.com/8GwkWei.png"/>
</p>

Quark-Engine is also bundled with [Kali Linux](https://tools.kali.org/tools-listing), [BlackArch](https://blackarch.org/mobile.html).
:shipit:  A trust-worthy, practical tool that's ready to boost up your malware reverse engineering. <https://twitter.com/quarkengine>

## Quark Script - Ecosystem for Mobile Security Tools

#### Innovative & Interactive
The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or __pentest__ the targets.

Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to __interact__ with staged results and perform __creative__ analysis with Quark Script.

#### Dynamic & Static Analysis
In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. [objection](https://github.com/sensepost/objection)).  

#### Re-Usable & Sharable
Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges. 

#### More APIs to come
Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.  

### Introduce of Quark Script APIs

<details>
<summary><b>  Rule(rule.json) </b></summary>

<br>

* Description: Making detection rule a rule instance
* params: Path of a single Quark rule
* return: Quark rule instance

</details>
<details>
<summary><b>  runQuarkAnalysis(SAMPLE_PATH, ruleInstance) </b></summary>

<br>

* Description: Given detection rule and target sample, this instance runs the basic Quark analysis.
* params: 1. Target file 2. Quark rule object
* return: quarkResult instance

</details>
<details>
<summary><b>  quarkResultInstance.behaviorOccurList </b></summary>

<br>

* Description: List that stores instances of detected behavior in different part of the target file.
* params: none
* return: detected behavior instance

</details>
<details>
<summary><b>  quarkResultInstance.getAllStrings(none) </b></summary>

<br>

* Description: Get all strings inside the target APK file.
* params: none
* return: python list containing all strings inside the target APK file.

</details>
<details>
<summary><b>  behaviorInstance.firstAPI.fullName </b></summary>

<br>

* Description: Show the name of the first key API called in this behavior.
* params: none
* return: API name

</details>
<details>
<summary><b>  behaviorInstance.secondAPI.fullName </b></summary>

<br>

* Description: Show the name of the second key API called in this behavior.
* params: none
* return: API name

</details>
<details>
<summary><b>  behaviorInstance.hasUrl(none) </b></summary>

<br>

* Description: Check if the behavior contains urls.
* params: none
* return: python list containing all detected urls.

</details>
<details>
<summary><b>  behaviorInstance.methodCaller </b></summary>

<br>

* Description: Find method who calls this behavior (API1 & API2).
* params: none
* return: method instance 

</details>
<details>
<summary><b>  behaviorInstance.getParamValues(none) </b></summary>

<br>

* Description: Get parameter values that API1 sends to API2 in the behavior.
* params: none
* return: python list containing parameter values.

</details>
<details>
<summary><b>  methodInstance.getXrefFrom(none) </b></summary>

<br>

* Description: Find out who call this method.
* params: none
* return: python list containing caller methods.

</details>
<details>
<summary><b>  methodInstance.getXrefTo(none) </b></summary>

<br>

* Description: Find out who this method called.
* params: none
* return: python list containing tuples (callee methods, index).

</details>
<details>
<summary><b>  Objection(host) </b></summary>

<br>

* Description: Create an instance for Objection (dynamic analysis tool). 
* params: Monitoring IP:port
* return: objection instance

</details>
<details>
<summary><b>  objInstance.hookMethod(method, watchArgs, watchBacktrace, watchRet) </b></summary>

<br>

* Description: Hook the target method with Objection.
* params: 1. method: the tagrget API. (type: str or method instance) 2. watchArgs: Return Args information if True. (type: boolean) 3. watchBacktrace: Return backtrace information if True. (type: boolean) 4. watchRet: Return the return information of the target API if True (type: boolean).
* return: none

</details>

### Analyzing real case (InstaStealer) using Quark Script
#### Quark Script that dynamic hooks the method containing urls 
The scenario is simple! We'd like to dynamic hooking the methods in the malware that contains urls. We can use APIs above to write Quark Script.

```python
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
```
> Note: Please make sure you have the dynamic analysis environment ready before executing the script.
> 1. Objection installed and running. Check the guideline [here](https://github.com/sensepost/objection/wiki/Installation).
> 2. Android Virtual Machine with frida installed. Check the guideline [here](https://frida.re/docs/android/).
> 3. Or a rooted Android Device (Google Pixel 6) with frida installed. 
> Check the root guideline [here](https://forum.xda-developers.com/t/guide-root-pixel-6-with-magisk-android-12-1.4388733/), frida install guideline is the [same]((https://frida.re/docs/android/)) with Android Virtual Machine.

#### Quark Script Result
![](https://i.imgur.com/elztZdC.png)

#### Logs on the Objection terminal (hooking)
![](https://i.imgur.com/XrtfgjY.jpg)

#### Method (callComponentMethod) with urls is detected triggered!
![](https://i.imgur.com/ryV3f57.jpg)

### Quark Script used as a vulnerability finder

####  Detect CWE-798 in Android Application

This scenario seeks to find hard-coded credentials in the APK file. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) for more details.

Let's use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule `findSecretKeySpec.json` to spot on behavior uses method SecretKeySpec. Then, we get all the parameter values that input to this method. From the returned parameter values, we identify it's a AES key and parse the key out of the values. Finally, we dump all strings in the APK file and check if the AES key is in the strings. If the answer is YES, BINGO!!! We find hard-coded credentials in the APK file. 

#### Quark Scipt: cwe-798.py
```python
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
```

#### Quark Rule: findSecretKeySpec.json
```json
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
```

#### Quark Script Result
```bash
$ python3 findSecretKeySpec.py 

Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f
```

#### Hard-Coded AES key in the APK file
```
const-string v2, "49u5gh249gh24985ghf429gh4ch8f23f"

invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B

move-result-object v2

invoke-direct {v1, v2, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```




## Quark Web Report

With the following command, you can easily analyze the Android sample and output the web report.

See our demo [here](https://pulorsok.github.io/ruleviewer/web-report-demo).

```bash
quark -a sample.apk -s -w quark_report.html
```

![](https://i.imgur.com/hG3Ag8t.png)

## Navigate the Rules

To navigate the latest rules for Quark, please visit the [Detection Rules Viewer](https://quark-engine.github.io/ruleviewer/)! In this viewer, you can use labels and keywords to search for the rules you need.

<details>
<summary>Illustration</summary>

![An illustration of the rule viewer](https://camo.githubusercontent.com/d2218ac92c2f4bff21dad45ddd693f1e2d61cc173fb89d4ce17c727d8375b379/68747470733a2f2f692e696d6775722e636f6d2f626f44535862662e676966)

</details>

## Why Quark?

Android malware analysis engine is not a new story. Every antivirus company has their own secrets to build it. With curiosity, we develop a malware scoring system from the perspective of Taiwan Criminal Law in an easy but solid way.

We have an order theory of criminal which explains stages of committing a crime. For example, crime of murder consists of five stages, they are determined, conspiracy, preparation, start and practice. The latter the stage the more we’re sure that the crime is practiced.

According to the above principle, `we developed our order theory of android malware`. We developed five stages to see if the malicious activity is being practiced. They are 1. Permission requested. 2. Native API call. 3. Certain combination of native API. 4. Calling sequence of native API. 5. APIs that handle the same register. We not only define malicious activities and their stages but also develop weights and thresholds for calculating the threat level of a malware.

Malware evolved with new techniques to gain difficulties for reverse engineering. Obfuscation is one of the most commonly used techniques. In this talk, we present a Dalvik bytecode loader with the order theory of android malware to neglect certain cases of obfuscation.

Our Dalvik bytecode loader consists of functionalities such as 1. Finding cross reference and calling sequence of the native API. 2. Tracing the bytecode register. The combination of these functionalities (yes, the order theory) not only can neglect obfuscation but also match perfectly to the design of our malware scoring system.

## Easy to Use and Reading Friendly Report

Quark provides **7 flexible report formats** and **2 powerful features** to boost your analysis.

7 Types of Report Formats:

-   [Summary Report](https://github.com/quark-engine/quark-engine#summary-report)
-   [Detail Report](https://github.com/quark-engine/quark-engine#detail-report)
-   [Web Report](https://github.com/quark-engine/quark-engine#quark-web-report)
-   [Label-based Report](https://github.com/quark-engine/quark-engine#label-based-report)
-   [Behaviors Comparison Radar Chart](https://github.com/quark-engine/quark-engine#behaviors-comparison-radar-chart)
-   [Call Graph](https://github.com/quark-engine/quark-engine#call-graph-for-every-potential-malicious-activity)
-   [Rule Classification](https://github.com/quark-engine/quark-engine#rules-classification)

2 Features to Boost Your Analysis:

-   [Radiocontrast](https://github.com/quark-engine/quark-engine#behaviors-comparison-radar-chart)
-   [Parallelizing Quark](https://github.com/quark-engine/quark-engine#parallelizing-quark)

Please see below for more details.

## Quick Start

### Requirements

-   Python 3.8+
-   git
-   graphviz
-   click >= 8.0.1 (For CLI supports)

### Installation

```bash
$ pip3 install -U quark-engine
```

### Get the Latest Rules

Now you can download [the Quark official ruleset](https://github.com/quark-engine/quark-rules) to your home directory with a simple command.

```bash
$ freshquark
```

Check `--help` to see the detailed usage description.

```bash
$ quark --help
```

### Test It Out

You may refer to the [Quark Engine Document](https://quark-engine.readthedocs.io/en/latest/) for more details of testing and development information.

## Available Report or Features

### Summary Report

Examine with rules.

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s
```

There is the possibility to select only one label to filter the rules:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s network
```

There is also the possibility to select only one rule:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s <path_to_the_rule>
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/v7ehRW0.png)

</details>

Note that if you want to select the default rules of Quark, the path to the ruleset is `$HOME/.quark-engine/quark-rules/rules/`.

### Detail Report

This is how we examine a real android malware (candy corn) with one single rule (crime).

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d
```

There is the possibility to select only one label to filter the rules:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d network
```

There is also the possibility to select only one rule:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d <path_to_the_rule>
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/LFLFpvc.png)

</details>

Note that if you want to select the default rules of Quark, the path to the ruleset is `$HOME/.quark-engine/quark-rules/rules/`.

### Label-based Report

Check which topic (indicated by [labels](https://github.com/quark-engine/quark-rules/blob/master/label_desc.csv)) of the malware is more aggressive.

```bash
quark -a Ahmyth.apk -l detailed
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/0GbBDfn.png)

</details>

### Behaviors Comparison Radar Chart

With the following command, you can compare different APK actions based on the max confidence of rule labels and generate
a radar chart.

```bash
quark -a first.apk -a second.apk -C
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/ClRWOei.png)

</details>

### Call Graph for Every Potential Malicious Activity

You can add the `-g` option to the quark command, and you can
get the call graph (only those rules match with 100% confidence)

```bash
quark -a Ahmyth.apk -s -g
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/5xcrcdN.png)

</details>

### Rules Classification

You can add the `-c` option to the quark command, and you can
output the rules classification with the mutual parent function (only those rules match with 100% confidence).

```bash
quark -a Ahmyth.apk -s -c
```

<details>
<summary>Result</summary>

![](https://i.imgur.com/YTK8V1x.png)

</details>

### Radiocontrast

Radiocontrast is a Quark API that quickly generates Quark rules from a specified method. It builds up 100% matched rules by using native APIs in that method. The feature lets you easily expose the behavior of a method, just like radiocontrast.

For example, we want to know the behavior of a method called `Lahmyth/mine/king/ahmyth/CameraManager;->startUp(I)V,` in Ahmyth.apk.
Here is the simplest way for Radiocontrast usage:

```python
from quark.radiocontrast import RadioContrast

# The target APK.
APK_PATH = "~/apk-malware-sample/Ahmyth.apk"

# The method that you want to generate rules. 
TARGET_METHOD = "Lahmyth/mine/king/ahmyth/CameraManager;->startUp(I)V"

# The output directory for generated rules.
GENERATED_RULE_DIR = "~/generated_rules"

radiocontrast = RadioContrast(
 APK_PATH, 
 TARGET_METHOD, 
 GENERATED_RULE_DIR
)

# param: web_editor: the file path for generated rules web editor.
# param: percentile_rank: the percentile number of api filter rank. 
#        For example, percentile_rank=0.2 use 20% least usage count APIs to generate rules
radiocontrast.generate_rule(percentile_rank=0.2, web_editor="ahmyth.html")
```

### Parallelizing Quark

Now Quark supports multiprocessing for analyzing APKs parallelly. By adding the option `--multi-process`, you can set the number of processes. 

Note that Quark-Engine automatically limits this value to be less than or equal to the number of CPUs - 1. This restriction is done to avoid the CPU from running out of memory. 

```bash
quark -a Ahmyth.apk -s --multi-process 4
```

### Upcoming Unstable Feature

Now Quark also supports [Rizin](https://github.com/rizinorg/rizin) as one of our Android analysis frameworks. You can use option `--core-library` with `rizin` to enable the Rizin-based analysis library.

```bash
quark -a Ahmyth.apk -s --core-library rizin
```

## Acknowledgments

#### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=115 height=150 src="https://i.imgur.com/znu7cMJ.png" alt="Honeynet.org logo"> </a>

#### Google Summer Of Code

Quark-Engine has been participating in the GSoC under the Honeynet Project!

-   2021:
    -   [YuShiang Dang](https://twitter.com/YushianhD): [New Rule Generation Technique & Make Quark Everywhere Among Security Open Source Projects](https://quark-engine.github.io/2021/08/17/GSoC-2021-YuShiangDang/)
    -   [Sheng-Feng Lu](https://twitter.com/haeter525): [Replace the core library of Quark-Engine](https://quark-engine.github.io/2021/08/17/GSoC-2021-ShengFengLu/)

Stay tuned for the upcoming GSoC! Join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.

## Core Values of Quark Engine Team

-   We love **battle fields**. We embrace **uncertainties**. We challenge **impossibles**. We **rethink** everything. We change the way people think. 
    And the most important of all, we benefit ourselves by benefit others **first**.
