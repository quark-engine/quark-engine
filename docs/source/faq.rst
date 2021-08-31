
FAQ
================

I have some questions. Where can I ask?
---------------------------------------

We welcome you to post your questions on our GitHub repository or our Telegram. We'll try our best to answer your questions as soon as possible,  but not be instant since we're focusing on adding new features into Quark-Engine!
Also, please understand that we may not answer questions about personal information since we want to keep them as our privacy. 

I got an error while using Quark-Engine. What can I do?
-------------------------------------------------------

Please use ``pip3 install quark-engine --upgrade`` to update your Quark-Engine and use ``freshquark`` to update rules first, then inspect if there are misspellings in the command. 
Here are two common errors that will occur. If those errors happened to you too, please check out the following information.


#. Errors on arguments (Reference to issue `#239 <https://github.com/quark-engine/quark-engine/issues/239>`_\ ): This type of error is usually caused by an outdated version of packages. Please update Quark Engine and the related python package first, then check if the problem still exists.
#. Errors on rules not found (Reference to `issue #237 <https://github.com/quark-engine/quark-engine/issues/237>`_\ ): Please update Quark-Rule with ``freshquark`` first. Since the way to specify rules is by adding ``<path_to_the_rule>`` as an argument, you need to input ``<path_to_the_rule>`` if the rule file is not in the current folder. If you want to select one of the rules of Quark-Rule, the default path to Quark-Rule is ``$HOME/.quark-engine/quark-rules/``.
   
   
How do threshold, score, and weight working in Quark Engine?
------------------------------------------------------------

About those details, we have a video to explain how it works. You can check out the video on YouTube:
https://www.youtube.com/watch?v=SOH4eqrv9_g

Why do scores keeping the same in all the analyses?
---------------------------------------------------

The default value is one since we would like users to define these numbers themselves, and we are still doing experiments to adjust the numbers.

How can I write a rule?
-----------------------

We have a detailed introduction to add rules. You can check it out `here <https://quark-engine.readthedocs.io/en/latest/addRules.html>`_.

How can I contribute my rules?
------------------------------

Feel free to make a pull request on the `Quark-Rule repository <https://github.com/quark-engine/quark-rules>`_. We appreciate your contribution to Quark-Engine!

Can I take part and contribute to Quark?
----------------------------------------

That's a big YES! We welcome anyone interested of Quark-Engine. Please check out our `development document <https://quark-engine.readthedocs.io/en/latest/dev_index.html>`_ and join our Telegram.
