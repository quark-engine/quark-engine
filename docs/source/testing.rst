++++++++++++++++++++
Testing Quark-Engine
++++++++++++++++++++

Firstly let's fetch some apk examples.

.. code-block:: bash

    $ git clone https://github.com/quark-engine/apk-samples.git


Then we could test one of the apk in `apk-samples` by the rules `quark-rules`. For example:

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

