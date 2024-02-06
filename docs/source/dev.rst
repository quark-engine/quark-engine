=================
Development Notes
=================

Git Branching Model
===================

Quark-engine source code is available in our `official Git repository`_.

.. _`official Git repository`: https://github.com/quark-engine/quark-engine

We have 6 branches.

    * **master**:

        - This is the stable and releasing branch.

    * **dev**:

        - This is where we commit our beta version.
        - When all the features are fully tested, it will be merged to ``master`` branch.

    * **feature**:

        - This is where we develop new features for the project.
        - Once it's done, it will be merged to ``dev`` branch.


    * **testing**:

        - This is where we write tests for the codebase and new feature.
        - When it's done, it will be merged to ``dev`` branch.

    * **hotfix**:

        - This branch is used to fix bugs.
        - Will be merged to ``dev`` and ``master``

    * **doc**:

        - This is where we update our documentation.
        - Just like hotfix branch, will be merged to ``dev`` and ``master``.

Release Versioning
==================

Our versioning logic is quite simple. We use the year and month of the release
as a version number. ``v19.10`` means we release this version in Oct. 2019.

Ticketing System
================

To submit reports or feature requests, please use GitHub's `Issue`_ tracking system.

.. _`Issue`: https://github.com/quark-engine/quark-engine/issues

Contribute
==========

To submit your patch, just create a Pull Request from your GitHub fork.
If you don't know how to create a Pull Request take a look to `GitHub help`_.

.. _`GitHub help`: https://help.github.com/articles/using-pull-requests/

Packaging
==========

Kali Linux
-----------

Steps For Packaging
"""""""""""""""""""""

Quark is available in  the Kali Linux repository. So you can install Quark with ``apt install quark-engine`` in Kali Linux. However, you can also create your own Kali package with the steps below.

**Step 1: Setup environment for packaging**

 
Install the necessary packages in the latest version of `Kali Linux <https://www.kali.org>`_.
 
.. code-block:: bash
    
    sudo apt update && apt-get install git python3 python3-pip \
    build-essential debhelper devscripts equivs

**Step 2: Download the source code of Quark**

Download the source code of Quark to the ``quark-engine`` directory.

.. code-block:: bash
    
    git clone https://github.com/quark-engine/quark-engine.git

Enter the ``quark-engine`` directory.

.. code-block:: bash
    
    cd quark-engine

**Step 3: Update the version information (optional)**

You can update the version number and changelog of the package. If you want to update the version number, change ``Standards-Version`` in the ``debian/control`` file. If you want to update the changelog, add the descriptions of new changes at the beginning of the ``debian/changelog`` file following the `Debian changelog format <https://www.debian.org/doc/manuals/maint-guide/dreq.en.html#changelog>`_.

 
**Step 4: Create the package**
 
Create a package for Kali Linux.

.. code-block:: bash
    
    dpkg-buildpackage -us -uc -b

Go to the previous directory.

.. code-block:: bash
    
    cd ..

Then, you can see the package named ``quark-engine_<<version>>.deb``, where ``<<version>>`` is the version number defined in the ``debian/control`` file.


**Step 5: Install Quark**

Install Quark using the created package.

.. code-block:: bash
    
    sudo apt install ./quark-engine_<<version>>.deb


Get The Automatically Created Package
""""""""""""""""""""""""""""""""""""""

We have automated the above steps with a GitHub CI for convenience. Whenever receiving a pull request or commit, the GitHub CI will create a package automatically. Then, you can get the package with the steps below.

**Step 1: Navigate to the result page of the GitHub CI**

Click the ``Actions`` tab on the GitHub page of Quark.

.. image:: https://i.imgur.com/tpBB18r.png


Click the ``Kali Package CI`` workflow in the left sidebar.

.. image:: https://i.imgur.com/kAYOHdO.png


**Step 2: Download the Kali package of the specific PR or commit**

Click the pull request or commit you want.

.. image:: https://i.imgur.com/8bJkcAa.png


Download the ``kali-package`` artifact in the Artifacts area.

.. image:: https://i.imgur.com/rlfiBI4.png


Decompress the downloaded Zip file to get the package.

