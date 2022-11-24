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
    <img src="https://i.imgur.com/8GwkWei.png"/>
</p>

# Quark Script - Dig Vulnerabilities in the BlackBox

### Innovative & Interactive

*   The goal of Quark Script aims to provide an innovative way for mobile security researchers to analyze or **pentest** the targets.
*   Based on Quark, we integrate decent tools as Quark Script APIs and make them exchange valuable intelligence to each other. This enables security researchers to **interact** with staged results and perform **creative** analysis with Quark Script.

### Dynamic & Static Analysis

*   In Quark script, we integrate not only static analysis tools (e.g. Quark itself) but also dynamic analysis tools (e.g. [objection](https://github.com/sensepost/objection)).

### Re-Usable & Sharable

*   Once the user creates a Quark script for specific analysis scenario. The script can be used in another targets. Also, the script can be shared to other security researchers. This enables the exchange of knowledges.

### More APIs to come

*   Quark Script is now in a beta version. We'll keep releasing practical APIs and analysis scenarios.
*   **See API document [here](https://quark-engine.readthedocs.io/en/latest/quark_script.html#introduce-of-quark-script-apis).**

# CWE Showcases

[CWE-89](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-89-in-android-application-androgoat-apk) | [CWE-94](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-94-in-android-application-ovaa-apk) | [CWE-312](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-312-in-android-application-ovaa-apk) | [CWE-319](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-319-in-android-application-ovaa-apk) | [CWE-327](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-327-in-android-application-injuredandroid-apk) | [CWE-532](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-532-in-android-application-dvba-apk) | [CWE-749](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-749-in-android-application-mstg-android-java-apk) | [CWE-780](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-780-in-android-application-mstg-android-java-apk) | [CWE-798](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk) | [CWE-921](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-921-in-android-application-ovaa-apk) | [CWE-926](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-926-in-android-application-dvba-apk)

# Quick Start

In this section, we will show how to detect CWE-798 with Quark Script.

### Step 1: Environments Requirements

*   Quark requires Python 3.8 or above.

### Step 2: Install Quark Engine

*   Install Quark Engine by running:

```bash
$ pip3 install -U quark-engine
```

### Step 3: Prepare Quark Script, Detection Rule and the Sample File

1.  Get the CWE-798 Quark Script and the detection rule [here](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk).
2.  Get the sampe file (ovaa.apk) [here](https://github.com/dark-warlord14/ovaa/releases/tag/1.0).
3.  Put the script, detection rule, and sample file in the same directory.
4.  Edit accordingly to the file names:

```bash
SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "findSecretKeySpec.json"
# Now you are ready to run the script!
```

### Step 4: Run the script

```bash
$ python3 CWE-798.py

# You should now see the detection result in the terminal.
Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f
```

*   **Check the [document](https://quark-engine.readthedocs.io/en/latest/quark_script.html#quark-script) for more examples.**

# Acknowledgments

### The Honeynet Project

<a href="https://www.honeynet.org"> <img style="border: 0.2px solid black" width=115 height=150 src="https://i.imgur.com/znu7cMJ.png" alt="Honeynet.org logo"> </a>

### Google Summer Of Code

Quark-Engine has been participating in the GSoC under the Honeynet Project!

*   2021:
    *   [YuShiang Dang](https://twitter.com/YushianhD): [New Rule Generation Technique & Make Quark Everywhere Among Security Open Source Projects](https://quark-engine.github.io/2021/08/17/GSoC-2021-YuShiangDang/)
    *   [Sheng-Feng Lu](https://twitter.com/haeter525): [Replace the core library of Quark-Engine](https://quark-engine.github.io/2021/08/17/GSoC-2021-ShengFengLu/)

Stay tuned for the upcoming GSoC! Join the [Honeynet Slack chat](https://gsoc-slack.honeynet.org/) for more info.

# Core Values of Quark Engine Team

*   We love **battle fields**. We embrace **uncertainties**. We challenge **impossibles**. We **rethink** everything. We change the way people think. And the most important of all, we benefit ourselves by benefit others **first**.
