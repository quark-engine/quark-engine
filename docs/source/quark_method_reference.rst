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
        :param wrapper: list is used to track each function.
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


find_api_usage
==============

**The algorithm of find_api_usage**

The method searches for methods with ``method_name`` and ``descriptor_name``, that belong to either the ``class_name`` or its subclass. It returns a list of matching methods.

.. code-block:: TEXT

    1. Initialize an empty "method_list".
    2. Search for an exact match of the method by its "class_name", "method_name", and "descriptor_name".
        - If found, return a list with the matching methods.
    3. Create a list of potential methods with matching "method_name" and "descriptor_name".
    4. Filter the list of potential methods to include only those with bytecodes.
    5. Check if the class of each potential method is a subclass of the given "class_name".
        - If yes, add the method to "method_list".
    6. Return "method_list".

**The code of find_api_usage**

.. code-block:: python

    def find_api_usage(self, class_name, method_name, descriptor_name):
        method_list = []

        # Source method
        source_method = self.apkinfo.find_method(
            class_name, method_name, descriptor_name
        )
        if source_method:
            return [source_method]

        # Potential Method
        potential_method_list = [
            method
            for method in self.apkinfo.all_methods
            if method.name == method_name
            and method.descriptor == descriptor_name
        ]

        potential_method_list = [
            method
            for method in potential_method_list
            if not next(self.apkinfo.get_method_bytecode(method), None)
        ]

        # Check if each method's class is a subclass of the given class
        for method in potential_method_list:
            current_class_set = {method.class_name}

            while current_class_set and not current_class_set.intersection(
                {class_name, "Ljava/lang/Object;"}
            ):
                next_class_set = set()
                for clazz in current_class_set:
                    next_class_set.update(
                        self.apkinfo.superclass_relationships[clazz]
                    )

                current_class_set = next_class_set

            current_class_set.discard("Ljava/lang/Object;")
            if current_class_set:
                method_list.append(method)

        return method_list
