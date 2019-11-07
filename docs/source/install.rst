+++++++++++++++++++++++
Installing Quark-Engine
+++++++++++++++++++++++

Clone the project from Gitub::

    $ git clone https://github.com/quark-engine/quark-engine.git

Change directory to quark::

    $ cd quark-engine/quark

Install engine with pipenv::

    $ pipenv install

Launching subshell in virtual env::

    $ pipenv shell

Run the help cmd of quark::

    $ python main.py --help

Once you see the following msg, then you're all set::

    usage: main.py [-h] [-e] [-d] -a APK -r RULE

    optional arguments:
      -h, --help            show this help message and exit
      -e, --easy            show easy report
      -d, --detail          show detail report
      -a APK, --apk APK     APK file
      -r RULE, --rule RULE  Rules need to be checked

