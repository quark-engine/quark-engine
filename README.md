# Quark

![](https://i.imgur.com/eaz7Tfe.png)


## Installation

```bash=
$ git clone https://github.com/18z/quark-rules

$ cd quark-rules

$ pipenv install

$ pipenv shell
```

Make sure your python version is `3.7`, or you could change it from `Pipfile` to what you have.

## Usage

```bash
python main.py --help
```


```
usage: main.py [-h] [-e] [-d]

optional arguments:
  -h, --help    show this help message and exit
  -e, --easy    show easy report
  -d, --detail  show detail report
```

## Example (Easy report)
```
python main.py -e
```

![](https://i.imgur.com/OXYnR0r.png)

## Example (Detail report)
```
python main.py -d
```

![](https://i.imgur.com/DK8c3cL.png)
