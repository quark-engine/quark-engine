+++++++++++++++++++++++
Quark Method Reference
+++++++++++++++++++++++

quark.core.quark.py
--------------------

find_previous_method
=====================

**The algorithm of find_previous_method**

The find_previous_method method uses a DFS algorithm to collect all MethodObjects called by the parent_method and add them to the specified wrapper. The search starts from the base_method and goes on recursively until there are no more levels or all candidates have been processed.

.. code-block:: TEXT

    1. Initialize an empty set "visited_methods" if it is not provided.
    2. Get a set "method_set" using "self.apkinfo.upperfunc(base_method)".
    3. Add "base_method" to the "visited_methods" set.
    4. If "method_set" is not None then check if "parent_function" is in "method_set".
       - If yes, append "base_method" to "wrapper".
       - If no, then iterate through each item in "method_set".
            - If the item is in "visited_methods", skip it and continue to the next item.
            - If not, call "find_previous_method" again with the current item, "parent_function", "wrapper", and "visited_methods".

**The code of find_previous_method**

.. code-block:: python

    def find_previous_method(
        self, base_method, parent_function, wrapper, visited_methods=None
    ):
        """
        Find the method under the parent function, based on base_method before to parent_function.
        This will append the method into wrapper.

        :param base_method: the base function which needs to be searched.
        :param parent_function: the top-level function which calls the basic function.
        :param wrapper: python list, which contains the targeted parent_method.
        :param visited_methods: set with tested method.
        :return: None
        """
        if visited_methods is None:
            visited_methods = set()

        method_set = self.apkinfo.upperfunc(base_method)
        visited_methods.add(base_method)

        if method_set is not None:

            if parent_function in method_set:
                wrapper.append(base_method)
            else:
                for item in method_set:
                    # prevent to test the tested methods.
                    if item in visited_methods:
                        continue
                    self.find_previous_method(
                        item, parent_function, wrapper, visited_methods
                    )