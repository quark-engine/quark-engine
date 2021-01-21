<p align="center">
    <a href="https://conference.hitb.org/hitb-lockdown002/">
        <img alt="HITB" src="https://img.shields.io/badge/HITB-Lockdown%20002-red">
    </a>
    <a href="https://www.rootcon.org/html/recoverymode/talks">
        <img alt="rootcon" src="https://img.shields.io/badge/ROOTCON-2020-orange">
    </a>
    <a href="https://www.blueteamvillage.org/">
        <img alt="defcon" src="https://img.shields.io/badge/DEFCON%2028-BTV-blue">
    </a><br>
    <a href="https://travis-ci.org/quark-engine/quark-engine.svg?branch=master">
        <img alt="build status" src="https://travis-ci.org/quark-engine/quark-engine.svg?branch=master">
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


Quark-Engine is also bundled with [BlackArch](https://blackarch.org/mobile.html).
:shipit:  A trust-worthy, practical tool that's ready to boost up your malware reverse engineering. https://twitter.com/quarkengine

<img src="https://i.imgur.com/nz4m8kr.png"/>

[![asciicast](https://asciinema.org/a/376166.svg)](https://asciinema.org/a/376166)

## Why Quark?

Android malware analysis engine is not a new story. Every antivirus company has their own secrets to build it. With curiosity, we develop a malware scoring system from the perspective of Taiwan Criminal Law in an easy but solid way.

We have an order theory of criminal which explains stages of committing a crime. For example, crime of murder consists of five stages, they are determined, conspiracy, preparation, start and practice. The latter the stage the more we’re sure that the crime is practiced.

According to the above principle, ```we developed our order theory of android malware```. We develop five stages to see if the malicious activity is being practiced. They are 1. Permission requested. 2. Native API call. 3. Certain combination of native API. 4. Calling sequence of native API. 5. APIs that handle the same register. We not only define malicious activities and their stages but also develop weights and thresholds for calculating the threat level of a malware.

Malware evolved with new techniques to gain difficulties for reverse engineering. Obfuscation is one of the most commonly used techniques. In this talk, we present a Dalvik bytecode loader with the order theory of android malware to neglect certain cases of obfuscation.

Our Dalvik bytecode loader consists of functionalities such as 1. Finding cross reference and calling sequence of the native API. 2. Tracing the bytecode register. The combination of these functionalities (yes, the order theory) not only can neglect obfuscation but also match perfectly to the design of our malware scoring system.

### Easy to Use and Reading Friendly Report

Quark is very easy to use and also provides flexible output formats. There are 3 types of output report: detail report, call graph, and summary report. Please see below for more details.


#### Detail Report

This is a how we examine a real android malware (candy corn) with one single rule (crime).

```bash
$ quark -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
                 -r rules/ \
                 --detail
```

and the report will look like:

<img src="https://i.imgur.com/TFle3dL.png"/>

### Call Graph for Every Potential Malicious Activity
You can add the `-g` option to the quark command, and you can
get the call graph (only those rules match with 100% confidence)
```bash
quark -a Ahmyth.apk -r quark-rules/ -s -g
```
<img src="https://i.imgur.com/5xcrcdN.png"/>

### Rules Classification
You can add the `-c` option to the quark command, and you can
output the rules classification with mutual parent function (only those rules match with 100% confidence)
```bash
quark -a Ahmyth.apk -r quark-rules/ -s -c
```
<img src="https://i.imgur.com/YTK8V1x.png"/>

### Summary Report
Examine with rules.

```bash
quark -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
               -r rules/ \
               --summary
```
<img src="https://i.imgur.com/kxPYeIO.png"/>

## QuickStart

### Requirements
-   Python 3.7+
-   git

### Installation

```bash
$ pip install -U quark-engine
```

Quark now has a sweet feature that helps users to get the latest detection rules daily.

### Get the latest quark rules from our [quark-rules](https://github.com/quark-engine/quark-rules) repo

```bash
$ freshquark
```

Check `--help` to see the detailed usage description.

```bash
$ quark --help
```

### Test It Out

You may refer to the [Quark Engine Document](https://quark-engine.readthedocs.io/en/latest/) for more details of testing and development information.

## Analysis Reports of Real Malware

Quark Engine will soon provide analysis reports of real malware! For your best experience of viewing the report, please use desktop web browser. We're planning to make a mobile version of report. If you really want to see the very first version of report please visit [here](https://quark-engine.github.io/reports/report_5751cfdf656f2a5ee021940c5448a77e5b921d1510d2abfa520a57d02c74821e0f5c2e4935bea2554c440072d32fc22bb8317a85dabbbc7c9cca9d1c077793c2.html)

Also, we will soon give out our new detection rules! 

![](https://i.imgur.com/Wi9mPtx.png)
