++++++++++++++++++++
Testing Quark-Engine
++++++++++++++++++++

Firstly let's fetch some apk examples.

.. code-block:: bash

    $ git clone https://github.com/quark-engine/apk-malware-samples.git


Then we could test one of the apk in `apk-malware-samples` by the rules `quark-rules`. For example:

.. code-block:: bash

    $ quark -a Ahmyth.apk -s

Running in Docker
=================

We could build the corresponding docker image by this command:

.. code-block:: bash

    docker build . -t quark


When the image is ready, let's run an example to test the image:

You may also interactively use quark in the docker container. For example:

.. code-block:: bash

    $ docker run -v $(pwd):/tmp -it quark bash
    (in-docker): /app/quark# cd /tmp
    (in-docker)::/tmp# quark -a Ahmyth.apk -s

Running analyses based on Rizin (Upcoming unstable feature)
===========================================================

Now Quark also supports `Rizin`_ as one of our Android analysis frameworks. You can use option ``--core-library`` with ``rizin`` to enable the Rizin-based analysis library.

.. _`Rizin`: https://github.com/rizinorg/rizin

.. code-block:: bash

    quark -a Ahmyth.apk -s --core-library rizin


For now, Quark is compatible with Rizin v0.3.4. But, users don't have to installed a Rizin with that version. Quark provides a feature to automatically setup a independent Rizin. In this way, the dependency will not conflict with your environment. Type in the above command and let Quark handle everything else for you.

If there is a working installation of Rizin installed in the system, Quark will check its version to determine if it is compatible. If true, Quark automatically uses it for the analysis. Otherwise, Quark uses the independent Rizin installed in the Quark directory (``~/.quark-engine``).
