Quark Method Reference
======================

quark.core.qurk.py
------------------

find_previous_method
~~~~~~~~~~~~~~~~~~~~

-  **Description** The find_previous_method method uses a DFS algorithm
   to collect all MethodObjects called by the **parent_method** and add
   them to the specified **wrapper**. The search starts from the
   **base_method** and and goes on recursively until there are no more
   levels or all candidates have been processed.

-  **Param**

   -  **base_method**: the base function which needs to be searched.
   -  **parent_function**: the top-level function which calls the basic
      function.
   -  **wrapper**: list is used to track each function.
   -  **visited_methods**: set with tested method.

-  **Return** None
