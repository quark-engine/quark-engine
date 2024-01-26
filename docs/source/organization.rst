++++++++++++
Organization
++++++++++++

Quark Core Library Team
=======================

The Quark Core Library Team is responsible for developing and maintaining the core library of Quark, including developing and maintaining the Rizin-based and Radare2-based core library and defining processes for resolving core library issues. The goal is to build accurate and stable core libraries and to ensure the core libraries are continually updated. By leveraging the core libraries, Quark delivers reliable intelligence.

Core Library Team Operation Mechanism
--------------------------------------

.. image:: https://i.imgur.com/DAUlAAW.png

The team focuses on developing, maintaining, and enhancing the core libraries, with efforts in three dimensions: **issue resolution**, **steady updates**, and **new feature development**.

For **issue resolution**, they first evaluate the issue of the core library. Next, they report it to the relevant projects (Rizin, Radare2, or Quark) and push for fixes. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If the community reports a new issue, they start the process again.

For **steady updates**, they first develop a new version of the core library for the Rizin or Radare2 release. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If Rizin or Radare2 publish a new release, they start the process again.

For **new feature development**, they first discuss whether to accept the new feature. Next, they develop a new version of the core library to support the feature. Then, they ensure that the new core library meets the release criteria. Finally, they publish it in the next Quark release. If the community proposes a new feature, they start the process again.

The core library team will follow these processes to ensure the constant renovation and strengthening of the core library. Consequently, the core library achieves the goals of accuracy, stability, and continuous updating.

2024 Core Library Team Plan
---------------------------

* **The 1st Quarter** - We will develop the core library release criteria, define the process of resolving core library issues, and publish a beta release of the Rizin/Radare2 core library.

* **The 2nd Quarter** - We will develop an automated evaluation process for core library releases using GitHub CI and publish a pre-release of the Rizin/Radare2 core library.

* **The 3rd Quarter** - We will develop the selection criteria of Quark's main core library and publish a formal release of the Rizin/Radare2 core library.

* **The 4th Quarter** - We will replace the main core library and resolve the issues on tools integrating Quark because of the replacement.

Process for Resolving Core Library Issues
-----------------------------------------

When the team receives a core library issue, they resolve it as below.

.. image:: https://i.imgur.com/5nPnQwJ.png

Quark Script Team 
==================

The Quark Script Team is dedicated to the continual improvement of the Quark Script API. Our mission encompasses the development, maintenance, and enhancement of the API, documentation, and Quark Script Repo. We focus on developing methodologies for effective auditing and optimization, aiming to make the Quark Script API user-friendly, practical, and easily comprehensible for developers, contributors, and users.

Quark Script Team Operation Mechanism
--------------------------------------

.. image:: https://i.imgur.com/vHcYmPZ.png


Our approach integrates development, maintenance, and optimization of the Quark Script API. This comprehensive strategy covers both coding and documentation aspects.

* Code Aspect:
    - Development & Maintenance: We start by focusing on the development and regular upkeep of the Quark Script API.
    - Audit & Optimize: Following development, we conduct thorough audits and apply optimization techniques to enhance quality.
    - Practical Application: We identify areas for further refinement in real-world applications and circle back to development for continuous improvement.

* Documentation Aspect:
    - Authoring: Initial efforts involve creating clear and detailed API documentation.
    - Audit & Optimize: Similar to code, we audit and optimize the documentation to ensure its quality and readability.
    - Practical Application: Feedback from practical application helps us pinpoint areas for improvement in documentation, leading to subsequent revisions and enhancements.

2024 Quark Script Team Plan
---------------------------

* Q1: Audit and Optimization
    Focus on developing and refining audit and optimization methodologies for both the Quark Script API code and its documentation.
    Implement a complete cycle of these methodologies to ensure the highest standards.

* Q2: Development, Maintenance, and Documentation Enhancement
    Post-audit, emphasize further development and maintenance of the Quark Script API.
    Apply lessons from the audit phase to refine our development and documentation practices.

* Q3: Practical Application and Feedback Integration
    Engage in real-world application scenarios to identify unseen challenges.
    Utilize these insights for targeted development and documentation enhancements.

* Q4: Comprehensive Review and Strategy Refinement
    Review the year's methodologies and outcomes, focusing on development, maintenance, practical application, and auditing processes.
    Use these insights to refine our overall approach, ensuring continuous improvement and alignment with user needs.
    This revised version aims to eliminate redundancy, clarify processes, and provide a more structured approach to the Quark Script Team's operations and plans.

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
