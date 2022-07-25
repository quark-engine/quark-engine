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

### Innovative & Interactive
The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or __pentest__ the targets.

Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to __interact__ with staged results and perform __creative__ analysis with Quark Script.

### Dynamic & Static Analysis
In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. [objection](https://github.com/sensepost/objection)).  

### Re-Usable & Sharable
Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges. 

### More APIs to come
Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.  

__See API document [here](https://quark-engine.readthedocs.io/en/latest/quark_script.html#introduce-of-quark-script-apis).__
### 2022 CWE Top 25 Showcases
* [CWE-798](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk)
* [CWE-94](https://quark-engine.readthedocs.io/en/latest/quark_script.html#quark-scipt-cwe-94-py)

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
