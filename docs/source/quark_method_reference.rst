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

-  **Algorithm**

   1. Initialize an empty set **visited_methods** if it is not provided.
   2. Get a set **method_set** using
      **self.apkinfo.upperfunc(base_method)**
   3. Add **base_method** to the **visited_methods** set.
   4. If **method_set** is not **None**:

      -  

         a. Check if **parent_function** is in **method_set**.

         -  If yes, append **base_method** to **wrapper**.
         -  If no, then iterate through each item in **method_set**.

            -  If the item is in **visited_methods**, continue to the
               next item.
            -  If not, call **find_previous_method** again with the
               current item, **parent_function**, **wrapper**, and
               **visited_methods**.
