# Quark Engine [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/18z/quark-rules/blob/master/LICENSE) ![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)
An Obfuscation-Neglect Android Malware Scoring System


#### Installation

```bash=
$ git clone https://github.com/18z/quark-rules

$ cd quark-rules

$ pipenv install

$ pipenv shell
```

Make sure your python version is `3.7`, or you could change it from `Pipfile` to what you have.

#### Usage

```bash
python main.py --help
```


```
usage: main.py [-h] [-e] [-d] -a APK -r RULE

optional arguments:
  -h, --help            show this help message and exit
  -e, --easy            show easy report
  -d, --detail          show detail report
  -a APK, --apk APK     APK file
  -r RULE, --rule RULE  Rules need to be checked
```

#### Example (Easy report)
```
python main.py -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk -r rules/sendLocation.json -e
```
![](https://i.imgur.com/cNOsyO9.png)

#### Example (Detail report)
```
python main.py -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk -r rules/sendLocation.json -d
```

![](https://i.imgur.com/DK8c3cL.png)
