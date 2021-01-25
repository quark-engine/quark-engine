+++++++++++++++++++++++
Installing Quark-Engine
+++++++++++++++++++++++

PIP::

    $ pip install -U quark-engine

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
      -s, --summary                   Show summary report
      -d, --detail                    Show detail report
      -o, --output FILE               Output report as json file
      -a, --apk FILE                  APK file  [required]
      -r, --rule PATH                 Rules directory  [default: /Users/nick/.quark-engine/quark-rules]

      -g, --graph                     Creating call graph and save it to
                                      call_graph_image directory

      -c, --classification            Show rules classification
      -t, --threshold [100|80|60|40|20]
                                      Set the confidence threshold
      --help                          Show this message and exit.
