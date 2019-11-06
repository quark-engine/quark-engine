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
