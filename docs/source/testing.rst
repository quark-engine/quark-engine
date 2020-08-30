++++++++++++++++++++
Testing Quark-Engine
++++++++++++++++++++

Firstly let's fetch `rules` and some apk examples.

.. code-block:: bash

    $ git clone https://github.com/quark-engine/quark-rules.git
    $ git clone https://github.com/quark-engine/apk-malware-samples.git


Then we could test one of the apk in `apk-malware-samples` by the rules `quark-rules`. For example:

.. code-block:: bash

    $ quark -a ./apk-malware-samples/com.cdim.driver.core.apk -r quark-rules/ --summary


Running in Docker
=================

We could build the corresponding docker image by this command:

.. code-block:: bash

    docker build . -t quark


When the image is ready, let's run an example to test the image:

.. code-block:: bash

    docker run -it quark quark -a sample/14d9f1a92dd984d6040cc41ed06e273e.apk -r rules/ --summary


An apk `14d9f1a92dd984d6040cc41ed06e273e.apk` is then scanned by quark in this docker container, and deliver a report in summary format.

You may also interactively use quark in the docker container. For example:

.. code-block:: bash

    $ docker run -v $(pwd):/tmp -it quark bash
    (in-docker): /app/quark# cd /tmp
    (in-docker)::/tmp# quark -a ./apk-malware-samples/com.cdim.driver.core.apk -r quark-rules/ --summary

