+++++++++++++++++++++++
Installing Quark-Engine
+++++++++++++++++++++++


Step 1. Install Shuriken-Analyzer
--------------------------------------------


- Make sure you have the following packages installed:

  - C++ Compiler (`GCC13 <https://gcc.gnu.org/>`_ or `Microsoft Visual Studio <https://visualstudio.microsoft.com/>`_)
  - `CMake <https://cmake.org/>`_
  - `Git <https://git-scm.com/>`_
  - `iputils-ping <https://github.com/iputils/iputils/tree/master>`_ (Only required for Linux users)

- Install `Shuriken-Analyzer <https://github.com/Shuriken-Group/Shuriken-Analyzer>`_ by running::

    $ pip install git+https://github.com/Fare9/Shuriken-Analyzer.git@main#subdirectory=shuriken/bindings/Python/

- For example, to install Shuriken-Analyzer on Ubuntu, you can run the following commands:

  ::

    $ apt install build-essential g++-13 gcc-13 cmake git iputils-ping
    $ export CC=gcc-13 CXX=g++-13
    $ pip install git+https://github.com/Fare9/Shuriken-Analyzer.git@main#subdirectory=shuriken/bindings/Python/

Step 2. Install Quark-Engine
------------------------------

-  From PyPi:

  ::

        $ pip install -U quark-engine

-  Or you can install Quark-Engine from the source:

  ::

        $ git clone https://github.com/quark-engine/quark-engine.git
        $ cd quark-engine/
        $ pipenv install --skip-lock
        $ pipenv shell

Step 3. Check if Quark-Engine is installed
---------------------------------------------

- Run the help cmd of quark:

  ::

    $ quark --help

- Once you see the following message, then you’re all set:

  ::

    Usage: quark [OPTIONS]

      Quark is an Obfuscation-Neglect Android Malware Scoring System

    Options:
      -s, --summary TEXT              Show summary report. Optionally specify the
                                      name of a rule/label
      -d, --detail TEXT               Show detail report. Optionally specify the
                                      name of a rule/label
      -o, --output FILE               Output report in JSON
      -w, --webreport FILE            Generate web report
      -a, --apk FILE                  APK file  [required]
      -r, --rule PATH                 Rules directory  [default:
                                      /home/jensen/.quark-engine/quark-
                                      rules/rules]
      -g, --graph [png|json]          Create call graph to call_graph_image
                                      directory
      -c, --classification            Show rules classification
      -t, --threshold [100|80|60|40|20]
                                      Set the lower limit of the confidence
                                      threshold
      -i, --list [all|native|custom]  List classes, methods and descriptors
      -p, --permission                List Android permissions
      -l, --label [max|detailed]      Show report based on label of rules
      -C, --comparison                Behaviors comparison based on max confidence
                                      of rule labels
      --generate-rule DIRECTORY       Generate rules and output to given directory
      --core-library [androguard|rizin|radare2|shuriken]
                                      Specify the core library used to analyze an
                                      APK
      --multi-process INTEGER RANGE   Allow analyzing APK with N processes, where
                                      N doesn't exceeds the number of usable CPUs
                                      - 1 to avoid memory exhaustion.  [x>=1]
      --version                       Show the version and exit.
      --help                          Show this message and exit.


To learn how to scan multiple samples in a directory, please have a look at :ref:`Directory Scanning <dir_scan>`.
