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

The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or **pentest** the targets.

Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to **interact** with staged results and perform **creative** analysis with Quark Script.

### Dynamic & Static Analysis

In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. [objection](https://github.com/sensepost/objection)).

### Re-Usable & Sharable

Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges.

### More APIs to come

Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.

**See API document [here](https://quark-engine.readthedocs.io/en/latest/quark_script.html#introduce-of-quark-script-apis).**

# 2022 CWE Top 25 Showcases

*   [CWE-798](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk)
*   [CWE-94](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-94-in-android-application-ovaa-apk)
*   [CWE-921](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-921-in-android-application-ovaa-apk)
*   [CWE-312](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-312-in-android-application-ovaa-apk)
*   [CWE-89](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-89-in-android-application-androgoat-apk)

# Other CWE Showcases

*   [CWE-926](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-926-in-android-application-dvba-apk)
*   [CWE-749](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-749-in-android-application-mstg-android-java-apk)
*   [CWE-532](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-532-in-android-application-dvba-apk)
*   [CWE-780](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-780-in-android-application-mstg-android-java-apk)
*   [CWE-319](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-319-in-android-application-ovaa-apk)

## Quick Start

### Requirements

*   Python 3.8+
*   git
*   graphviz
*   click >= 8.0.1 (For CLI supports)

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

## Acknowledgments

#### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=115 height=150 src="https://i.imgur.com/znu7cMJ.png" alt="Honeynet.org logo"> </a>

#### Google Summer Of Code

Quark-Engine has been participating in the GSoC under the Honeynet Project!

*   2021:
    *   [YuShiang Dang](https://twitter.com/YushianhD): [New Rule Generation Technique & Make Quark Everywhere Among Security Open Source Projects](https://quark-engine.github.io/2021/08/17/GSoC-2021-YuShiangDang/)
    *   [Sheng-Feng Lu](https://twitter.com/haeter525): [Replace the core library of Quark-Engine](https://quark-engine.github.io/2021/08/17/GSoC-2021-ShengFengLu/)

Stay tuned for the upcoming GSoC! Join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.

## Quark MIT Program

Quark MIT aims to create a **WIN-WIN** for both new comers and the community. 

For new comers, the community helps you to build a stronger resume by creating specific works that fit the job description of your **DREAM JOB**.

For the community, Quark-Engine gets new energy by the work the new comers contribute. And the most important of all, the Quark community gets to **GROW**.

*   **Find more details [here](https://quark-engine.readthedocs.io/en/latest/quark_mit_program.html)**

![](https://i.imgur.com/xXilFs8.png)

## Core Values of Quark Engine Team

*   We love **battle fields**. We embrace **uncertainties**. We challenge **impossibles**. We **rethink** everything. We change the way people think.
    And the most important of all, we benefit ourselves by benefit others **first**.
