+++++++++++++++++++++++
Installing Quark-Engine
+++++++++++++++++++++++

PyPi::

    $ pip3 install -U quark-engine

Install from Source::

    $ git clone https://github.com/quark-engine/quark-engine.git
    $ cd quark-engine/
    $ pipenv install --skip-lock
    $ pipenv shell

Run the help cmd of quark::

    $ quark --help

Once you see the following msg, then you're all set::

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
                                      /home/$USER/.quark-engine/quark-rules]
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
      --core-library [androguard|rizin]
                                      Specify the core library used to analyze an
                                      APK
      --multi-process INTEGER RANGE   Allow analyzing APK with N processes, where
                                      N doesn't exceeds the number of usable CPUs
                                      - 1 to avoid memory exhaustion.  [x>=1]
     --version                       Show the version and exit.
      --help                          Show this message and exit.

To learn how to scan multiple samples in a directory, please have a look at :ref:`Directory Scanning <dir_scan>`
