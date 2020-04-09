# Quark Engine [![HITB Armory](https://img.shields.io/badge/HITBSecConf%20Armory-AMS%202020-blue)](https://conference.hitb.org/hitbsecconf2020ams/hitb-armory/) [![Build Status](https://travis-ci.org/quark-engine/quark-engine.svg?branch=master)](https://travis-ci.org/quark-engine/quark-engine.svg?branch=master) [![codecov](https://codecov.io/gh/quark-engine/quark-engine/branch/master/graph/badge.svg)](https://codecov.io/gh/quark-engine/quark-engine) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/18z/quark-rules/blob/master/LICENSE) [![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-360/)
An ```Obfuscation-Neglect``` Android Malware ```Scoring System```

<img src="https://i.imgur.com/8GwkWei.png"/>

Quark-Engine is also bundled with [BlackArch](https://blackarch.org/mobile.html).

[![asciicast](https://asciinema.org/a/292752.svg)](https://asciinema.org/a/292752)

### Concepts

Android malware analysis engine is not a new story. Every antivirus company has their own secrets to build it. With curiosity, we develop a malware scoring system from the perspective of Taiwan Criminal Law in an easy but solid way. 

We have an order theory of criminal which explains stages of committing a crime. For example, crime of murder consists of five stages, they are determined, conspiracy, preparation, start and practice. The latter the stage the more we’re sure that the crime is practiced. 

According to the above principle, ```we developed our order theory of android malware```. We develop five stages to see if the malicious activity is being practiced. They are 1. Permission requested. 2. Native API call. 3. Certain combination of native API. 4. Calling sequence of native API. 5. APIs that handle the same register. We not only define malicious activities and their stages but also develop weights and thresholds for calculating the threat level of a malware. 

Malware evolved with new techniques to gain difficulties for reverse engineering. Obfuscation is one of the most commonly used techniques. In this talk, we present a Dalvik bytecode loader with the order theory of android malware to neglect certain cases of obfuscation. 

Our Dalvik bytecode loader consists of functionalities such as 1. Finding cross reference and calling sequence of the native API. 2. Tracing the bytecode register. The combination of these functionalities (yes, the order theory) not only can neglect obfuscation but also match perfectly to the design of our malware scoring system.

### Detail Report
This is a how we examine a real android malware (candy corn) with one single rule (crime).

```bash
$ quark -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
                 -r rules/ \
                 --detail
```

<img src="https://i.imgur.com/kh1jpsQ.png"/>

### Summary Report
Examine with rules.

```bash
quark -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
               -r rules/ \
               --summary
```
<img src="https://i.imgur.com/Ib01V6k.png"/>

### Installation

```bash
$ git clone https://github.com/quark-engine/quark-engine.git; cd quark-engine/quark
$ pipenv install --skip-lock
$ pipenv shell
```

Make sure your python version is `3.7`, or you could change it from `Pipfile` to what you have.

### Usage

```bash
$ quark --help
Usage: quark [OPTIONS]

  Quark is an Obfuscation-Neglect Android Malware Scoring System

Options:
  -s, --summary         show summary report
  -d, --detail          show detail report
  -a, --apk FILE        APK file  [required]
  -r, --rule DIRECTORY  Rules folder need to be checked  [required]
  --help                Show this message and exit.
```


