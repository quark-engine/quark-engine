++++++++++++
Organization
++++++++++++

Quark core library team
=======================

The Quark core library team is responsible for developing and maintaining the core library of Quark, including developing and maintaining the Rizin-based and Radare2-based core library and defining processes for resolving core library issues. The goal is to build accurate and stable core libraries and to ensure the core libraries are continually updated. By leveraging the core libraries, Quark delivers reliable intelligence.

Core processes
--------------
``Version: v1.0``

.. image:: https://i.imgur.com/fLRGv5P.png

The team focuses on developing, maintaining, and enhancing the core libraries, with efforts in three dimensions: **issue resolution**, **steady updates**, and **new feature development**.

For **issue resolution**, they first evaluate the issue of the core library. Next, they report it to the relevant projects (Rizin, Radare2, or Quark) and push for fixes. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If the community reports a new issue, they start the process again.

For **steady updates**, they first develop a new version of the core library for the Rizin or Radare2 release. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If Rizin or Radare2 publish a new release, they start the process again.

For **new feature development**, they first discuss whether to accept the new feature. Next, they develop a new version of the core library to support the feature. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If the community proposes a new feature, they start the process again.

The core library team will follow these processes to ensure the constant renovation and strengthening of the core library. Consequently, the core library achieves the goals of accuracy, stability, and continuous updating.

Plan for 2024
-------------

* **The 1st Quarter** - We will develop the core library release criteria, define the process of resolving core library issues, and publish a beta release of the Rizin/Radare2 core library.

* **The 2nd Quarter** - We will develop an automated evaluation process for core library releases using GitHub CI and publish a pre-release of the Rizin/Radare2 core library.

* **The 3rd Quarter** - We will develop the selection criteria of Quark's main core library and publish a formal release of the Rizin/Radare2 core library.

* **The 4th Quarter** - We will replace the main core library and resolve the issues on tools integrating Quark because of the replacement.

----

Quark triage team
=================

The Quark triage team handles more than just triage. They are the managers of the Quark organization. They define processes for handling issues/PRs, manage Quark releases. And the most important of all, they communicate with community members.

Responsibilities
----------------
``Version: v1.0``

* Management of issues within the Quark Github organization, including:
    - Review, close issues and apply appropriate labels for issues.
    - Resolve minor issues (typo, usage problem, ask about the Quark’s techniques).
    - Initiate a discussion with other members if the issues are major changes.
    - Define and revise the process for handling issues.

* Management of PRs within the Quark Github organization, including:
    - Review, merging PRs and applying appropriate labels for PRs.
    - Initiate a discussion with other members if the PRs are major changes.
    - Define and revise the process for handling PRs.

* Management of Quark releases on Kali/PyPi/Github, including:
     - Generate and create releases.
     - Test releases.
     - Define and revise the process and determine the content for releases.

Triage process
---------------
``Version: v1.1``

When Quark received an issue, the triage process is as below:

.. image:: https://i.imgur.com/iFFqcYx.png

.. note::
    **If the issue is unable to reproduce, and the issue raiser hasn't responded.**

    - **Over one month**, the assignee should apply the label ``more-info-require`` to the issue and ask for more information.
    - **Over two months**, the assignee should apply the label ``invalid`` to the issue and close it.

When Quark received a PR, the triage process is as below:

.. image:: https://i.imgur.com/jEkZSV8.png


Release process
----------------
``Version: v1.0``

The Quark release process is as below:

.. image:: https://i.imgur.com/WFifONc.png