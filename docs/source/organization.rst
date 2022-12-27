++++++++++++
Organization
++++++++++++

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

Quark CWE team
===============

The Quark CWE team is responsible for developing Quark Scripts to detect Common Weakness Enumeration (CWE) vulnerabilities in APKs. We also maintain the Quark Script document, API, and repository.

Goals for 2023
---------------

Our goals for 2023 consist of three stages. First, we will focus on increasing the number of CWE Quark Scripts to 30 and optimizing the Quark Script API by developing CWE Quark Scripts.

Next, with a sufficient number of Quark Scripts, we will develop a system to automatically detect vulnerabilities in online APKs.

Finally, based on the sufficient and quality Quark Script API, we will focus on developing a web system that allows users to easily combine Quark Script APIs and create their own scripts without any coding knowledge.

Responsibilities
-----------------

``Version: v1.0``

We aims to make the Quark Script development process as straightforward as possible, while ensuring that the scripts are accurate and reliable. We strive to create clear and concise documentation, as well as well-designed APIs that are easy to use. Our responsibilities include:

- Developing Quark Scripts through a five-step process:
    1. Choosing a CWE number and clearly explaining the vulnerability definition.
    2. Finding an APK sample and explaining the vulnerable code.
    3. Designing the detection process step by step.
    4. Defining a new Quark Script API (including description, input, and output) if necessary.
    5. Developing the Quark Script in a clear and easy-to-use manner.
- Managing the Quark Script repository by:
    - Updating the repository with new Quark Scripts.
    - Updating the documentation for Quark Scripts.
- Maintaining the Quark Script API by:
    - Developing test units for each Quark Script API.
    - Reviewing and modifying the description, input, and output for each API.
    
We aim to ensure that all of our work is easy to read and follows proper grammar and usage.