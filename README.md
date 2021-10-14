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
    <a href="https://t.me/joinchat/HrOyhhipvoFjOYc7mc941w">
        <img alt="Telegram" src="https://img.shields.io/badge/telegram-eff?logo=telegram">
    </a><br>
    <b> An Obfuscation-Neglect Android Malware Scoring System</b>
    <img src="https://i.imgur.com/8GwkWei.png"/>
</p>


Quark-Engine is also bundled with [Kali Linux](https://tools.kali.org/tools-listing), [BlackArch](https://blackarch.org/mobile.html).
:shipit:  A trust-worthy, practical tool that's ready to boost up your malware reverse engineering. https://twitter.com/quarkengine

## Available In

<img src="https://i.imgur.com/oQcqRXy.png"/>

<img src="https://i.imgur.com/nz4m8kr.png"/>

[![asciicast](https://asciinema.org/a/416810.svg)](https://asciinema.org/a/416810)

## Why Quark?

Android malware analysis engine is not a new story. Every antivirus company has their own secrets to build it. With curiosity, we develop a malware scoring system from the perspective of Taiwan Criminal Law in an easy but solid way.

We have an order theory of criminal which explains stages of committing a crime. For example, crime of murder consists of five stages, they are determined, conspiracy, preparation, start and practice. The latter the stage the more we’re sure that the crime is practiced.

According to the above principle, ```we developed our order theory of android malware```. We developed five stages to see if the malicious activity is being practiced. They are 1. Permission requested. 2. Native API call. 3. Certain combination of native API. 4. Calling sequence of native API. 5. APIs that handle the same register. We not only define malicious activities and their stages but also develop weights and thresholds for calculating the threat level of a malware.

Malware evolved with new techniques to gain difficulties for reverse engineering. Obfuscation is one of the most commonly used techniques. In this talk, we present a Dalvik bytecode loader with the order theory of android malware to neglect certain cases of obfuscation.

Our Dalvik bytecode loader consists of functionalities such as 1. Finding cross reference and calling sequence of the native API. 2. Tracing the bytecode register. The combination of these functionalities (yes, the order theory) not only can neglect obfuscation but also match perfectly to the design of our malware scoring system.

## Easy to Use and Reading Friendly Report

Quark is very easy to use and also provides flexible output formats. There are 6 types of output reports: detail report,
call graph, rules classification, summary report, label-based report, behaviors comparison radar chart. Please see below for more details.


### Detail Report

This is how we examine a real android malware (candy corn) with one single rule (crime).

```bash
$ quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d
```

and the report will look like:

<img src="https://i.imgur.com/g28N7qk.png"/>

There is the possibility to select only one label to filter the rules:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d network
```
There is also the possibility to select only one rule:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -d 00058.json
```

### Call Graph for Every Potential Malicious Activity
You can add the `-g` option to the quark command, and you can
get the call graph (only those rules match with 100% confidence)
```bash
quark -a Ahmyth.apk -s -g
```
<img src="https://i.imgur.com/5xcrcdN.png"/>

### Rules Classification
You can add the `-c` option to the quark command, and you can
output the rules classification with the mutual parent function (only those rules match with 100% confidence).
```bash
quark -a Ahmyth.apk -s -c
```
<img src="https://i.imgur.com/YTK8V1x.png"/>

### Summary Report
Examine with rules.

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s
```
<img src="https://i.imgur.com/v7ehRW0.png"/>

There is the possibility to select only one label to filter the rules:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s network
```
There is also the possibility to select only one rule:

```bash
quark -a 14d9f1a92dd984d6040cc41ed06e273e.apk -s <path_to_rule_folder>/00058.json
```
(If you want to select one of the rules of Quark-Rule, the default path to Quark-Rule is `$HOME/.quark-engine/quark -rules/`.)

### Label-based Report
Check which topic (indicated by [labels](https://github.com/quark-engine/quark-rules/blob/master/label_desc.csv)) of the malware is more aggressive.

```bash
quark -a Ahmyth.apk -l detailed
```
<img src="https://i.imgur.com/0GbBDfn.png"/>

### Behaviors Comparison Radar Chart
With the following command, you can compare different APK actions based on the max confidence of rule labels and generate
a radar chart.

```bash
quark -a first.apk -a second.apk -C
```

<img src="https://i.imgur.com/ClRWOei.png"/>

### Parallelizing Quark
Now Quark supports multiprocessing for analyzing APKs parallelly, by adding the option `--multi-process` and set the number of processes. (the default is the number of CPUs in your computer.)
```bash
quark -a Ahmyth.apk -s --multi-process 4
```

### Upcoming unstable feature
Now Quark also supports [Rizin](https://github.com/rizinorg/rizin) as one of our Android analysis frameworks. You can use option `--core-library` with `rizin` to enable the Rizin-based analysis library.
```bash
quark -a Ahmyth.apk -s --core-library rizin
```

## QuickStart

### Requirements
-   Python 3.8+
-   git
-   graphviz
-   click >= 8.0.1 (For CLI supports)

### Installation

```bash
$ pip3 install -U quark-engine
```

### Get the latest quark rules from our [quark-rules](https://github.com/quark-engine/quark-rules) repo

Now you can download the quark-rules to your home directory with a simple command.

```bash
$ freshquark
```

Check `--help` to see the detailed usage description.

```bash
$ quark --help
```

### Test It Out

You may refer to the [Quark Engine Document](https://quark-engine.readthedocs.io/en/latest/) for more details of testing and development information.

## Acknowledgments

#### The Honeynet Project
<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=115 height=150 src="https://i.imgur.com/znu7cMJ.png" alt="Honeynet.org logo"> </a>

#### Google Summer Of Code

Quark-Engine has been participating in the GSoC under the Honeynet Project!

* 2021: Join us! [Projects available](https://www.honeynet.org/gsoc/gsoc-2021/google-summer-of-code-2021-project-ideas/)

Stay tuned for the upcoming GSoC! Join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.

## Core Values of Quark Engine Team

* We love **battle fields**. We embrace **uncertainties**. We challenge **impossibles**. We **rethink** everything. We change the way people think. 
And the most important of all, we benefit ourselves by benefit others **first**.
