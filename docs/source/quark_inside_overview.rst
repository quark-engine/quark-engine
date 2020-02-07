=============================
Quark-Engine Project Overview
=============================

Quark-Engine Map
================

.. image:: https://i.imgur.com/FEZh3SB.png


The entire Quark-Engine project can be composed of four major parts, namely

* Five-stage rule
* Dalvik Bytecode Loader
* Scoring System
* Self-define objects data structure


Quark module architecture diagram
=================================

.. image:: https://i.imgur.com/8B2oV7c.png

The project is divided into three main folders.

Objects
-------

.. image:: https://i.imgur.com/sw5q0Qn.png

The Objects directory is used to store all the main self define objects,
including APK information object, Bytecode object, rule object, variable
tracking table object, variable object, and five-stage rule object.

Evaluator
---------

.. image:: https://i.imgur.com/yinL9P3.png

The Evaluator directory is used to store the Dalvik Bytecode Loader. The name
comes from the CPython virtual machine used to execute the python bytecode. The
Bytecode Loader itself is a huge switch. When the corresponding Bytecode
instruction is given, our customized function event will be executed. However,
the bytecode instruction does not interact with the CPU, so it is faster than
executing Android DEX files dynamically.

utils
-----

.. image:: https://i.imgur.com/O6w93vs.png

The utils directory is used to store repetitive tool code, print output
control, and weighted score calculations.