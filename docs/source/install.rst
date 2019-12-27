+++++++++++++++++++++++
Installing Quark-Engine
+++++++++++++++++++++++

Clone the project from Gitub::

    $ git clone https://github.com/quark-engine/quark-engine.git

Change directory to quark::

    $ cd quark-engine/quark

Install engine with pipenv::

    $ pipenv install --skip-lock

Launching subshell in virtual env::

    $ pipenv shell

Run the help cmd of quark::

    $ quark --help

Once you see the following msg, then you're all set::

    Usage: quark [OPTIONS]

    Quark is an Obfuscation-Neglect Android Malware Scoring System

    Options:
      -s, --summary         show summary report
      -d, --detail          show detail report
      -a, --apk FILE        APK file  [required]
      -r, --rule DIRECTORY  Rules folder need to be checked  [required]
      --help                Show this message and exit.
