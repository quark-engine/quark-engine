# Quark Engine [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/18z/quark-rules/blob/master/LICENSE) ![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)
An ```Obfuscation-Neglect``` Android Malware ```Scoring System```

### Concepts

Android malware analysis engine is not a new story. Every antivirus company has their own secrets to build it. With curiosity, we develop a malware scoring system from the perspective of Taiwan Criminal Law in an easy but solid way. 

We have an order theory of criminal which explains stages of committing a crime. For example, crime of murder consists of five stages, they are determined, conspiracy, preparation, start and practice. The latter the stage the more we’re sure that the crime is practiced. 

According to the above principle, ```we developed our order theory of android malware```. We develop five stages to see if the malicious activity is being practiced. They are 1. Permission requested. 2. Native API call. 3. Certain combination of native API. 4. Calling sequence of native API. 5. APIs that handle the same register. We not only define malicious activities and their stages but also develop weights and thresholds for calculating the threat level of a malware. 

Malware evolved with new techniques to gain difficulties for reverse engineering. Obfuscation is one of the most commonly used techniques. In this talk, we present a Dalvik bytecode loader with the order theory of android malware to neglect certain cases of obfuscation. 

Our Dalvik bytecode loader consists of functionalities such as 1. Finding cross reference and calling sequence of the native API. 2. Tracing the bytecode register. The combination of these functionalities (yes, the order theory) not only can neglect obfuscation but also match perfectly to the design of our malware scoring system.

### Detailed Report
This is a how we examine a real android malware (candy corn) with one single rule (crime).

```bash
$ python main.py -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
                 -r rules/sendLocation.json \
                 --detail
```

<img src="https://i.imgur.com/DK8c3cL.png" data-canonical-src="https://i.imgur.com/DK8c3cL.png" width="500" height="400" />

### Summary Report
Examine with rules.

```bash
python main.py -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk \
               -r rules/sendLocation.json \
               --easy
```
<img src="https://i.imgur.com/cNOsyO9.png" data-canonical-src="https://i.imgur.com/cNOsyO9.png" width="650" height="200" />

### Installation

```bash
$ git clone https://github.com/18z/quark-rules; cd quark-rules
$ pipenv install
$ pipenv shell
```

Make sure your python version is `3.7`, or you could change it from `Pipfile` to what you have.

### Usage

```bash
$ python main.py --help
usage: main.py [-h] [-e] [-d] -a APK -r RULE

optional arguments:
  -h, --help            show this help message and exit
  -e, --easy            show easy report
  -d, --detail          show detail report
  -a APK, --apk APK     APK file
  -r RULE, --rule RULE  Rules need to be checked
```


