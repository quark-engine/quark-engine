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
                    
find_intersection
=====================

**The algorithm of find_intersection**

The ``find_intersection`` method takes in two sets, ``first_method_set`` and ``second_method_set``, and finds their intersection using a recursive search algorithm.

Here is the process of ``find_intersection``。

.. code-block:: TEXT

    1. Check that the input sets are not empty. 
        If one of the sets is empty, raise a ValueError.
      
    2. Use the & operator to find the intersection of the two sets. 
        If the intersection is not empty, return the resulting set.
      
    3. If the intersection is empty, call the method_recursive_search 
        function with the input sets and a specified maximum depth.
      
    4. The method_recursive_search function recursively searches for 
        the intersection of the two input sets up to the specified depth 
        by splitting the sets into subsets and comparing each subset's elements. 
          - If the intersection is found, return the resulting set. 
          - Otherwise, return None.
      
**The code of find_intersection**

.. code-block:: python

    def find_intersection(self, first_method_set, second_method_set, depth=1):
        """
        Find the first_method_list ∩ second_method_list.
        [MethodAnalysis, MethodAnalysis,...]
        :param first_method_set: first list that contains each MethodAnalysis.
        :param second_method_set: second list that contains each MethodAnalysis.
        :param depth: maximum number of recursive search functions.
        :return: a set of first_method_list ∩ second_method_list or None.
        """
        # Check both lists are not null
        if not first_method_set or not second_method_set:
            raise ValueError("Set is Null")
        # find ∩
        result = first_method_set & second_method_set
        if result:
            return result
        else:
            return self.method_recursive_search(
                depth, first_method_set, second_method_set
            )

method_recursive_search
=======================

**The algorithm of method_recursive_search**

The ``method_recursive_search`` algorithm finds the intersection between
two sets of methods. Specifically, the algorithm expands each set by
recursively adding their respective upper-level method objects until it
finds an intersection or the depth reaches ``MAX_SEARCH_LAYER``.

Here is the process of ``method_recursive_search``.

.. code:: text

   1. The method_recursive_search function takes three arguments: 
       - depth, first_method_set, and second_method_set
   2. If the depth+1 > MAX_SEARCH_LAYER, return None.
   3. Create next_level_set_1 and next_level_set_2 that are the copies of first_method_set and second_method_set, respectively.
   4. Expand next_level_set_1 and next_level_set_2 by adding their respective upper-level methods.
   5. Calls find_intersection with the next_level_set_1, next_level_set_2 and depth+1 as arguments recursively.
       - If an intersection is found, return the result.
       - If no intersection is found, continue searching until depth > MAX_SEARCH_LAYER.

**The code of method_recursive_search**

.. code:: python

   def method_recursive_search(
       self, depth, first_method_set, second_method_set
   ):
       # Not found same method usage, try to find the next layer.
       depth += 1
       if depth > MAX_SEARCH_LAYER:
           return None

       # Append first layer into next layer.
       next_level_set_1 = first_method_set.copy()
       next_level_set_2 = second_method_set.copy()

       # Extend the xref from function into next layer.
       for method in first_method_set:
           if self.apkinfo.upperfunc(method):
               next_level_set_1 = (
                   self.apkinfo.upperfunc(method) | next_level_set_1
               )
       for method in second_method_set:
           if self.apkinfo.upperfunc(method):
               next_level_set_2 = (
                   self.apkinfo.upperfunc(method) | next_level_set_2
               )

       return self.find_intersection(
           next_level_set_1, next_level_set_2, depth
       )

find_api_usage
==============

**The algorithm of find_api_usage**

``find_api_usage`` searches for methods with ``method_name`` and ``descriptor_name``, that belong to either the ``class_name`` or its subclass. It returns a list that contains matching methods.

Here is the process of ``find_api_usage``.

.. code-block:: TEXT

    1. Initialize an empty "method_list".
    2. Search for an exact match of the method by its "class_name", "method_name", and "descriptor_name".
        - If found, return a list with the matching methods.
    3. Create a list of potential methods with matching "method_name" and "descriptor_name".
    4. Filter the list of potential methods to include only those with bytecodes.
    5. Check if the class of each potential method is a subclass of the given "class_name".
        - If yes, add the method to "method_list".
    6. Return "method_list".

Here is the flowchart of ``find_api_usage``.

.. image:: https://i.imgur.com/FZKRMgX.png

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
        
_evaluate_method
=====================

**The algorithm of _evaluate_method**

The ``_evaluate_method`` method evaluates the execution of opcodes in the target method and returns a matrix representing the usage of each involved register. The method takes one parameter, method, which is the method to be evaluated.

Here is the process of ``_evaluate_method``.

.. code-block:: TEXT

    1. Create a PyEval object with the apkinfo attribute of the instance. PyEval is presumably
    a class that handles the evaluation of opcodes.

    2. Loop through the bytecode objects in the target method by calling the get_method_bytecode 
    method of the apkinfo attribute.

    3. Extract the mnemonic (opcode), registers, and parameter from the bytecode_obj and create 
    an instruction list containing these elements.

    4. Convert all elements of the instruction list to strings (in case there are MUTF8String objects).

    5. Check if the opcode (the first element of instruction) is in the eval dictionary of the pyeval object. 
        - If it is, call the corresponding function with the instruction as its argument.

    6. Once the loop is finished, call the show_table method of the pyeval object to return the 
    matrix representing the usage of each involved register.

Here is the flowchart of ``_evaluate_method``.

.. image:: https://i.imgur.com/XCKrjjR.jpg
      
**The code of _evaluate_method**

.. code-block:: python

    def _evaluate_method(self, method) -> List[List[str]]:
        """
        Evaluate the execution of the opcodes in the target method and return
         the usage of each involved register.
        :param method: Method to be evaluated
        :return: Matrix that holds the usage of the registers
        """
        pyeval = PyEval(self.apkinfo)

        for bytecode_obj in self.apkinfo.get_method_bytecode(method):
            # ['new-instance', 'v4', Lcom/google/progress/SMSHelper;]
            instruction = [bytecode_obj.mnemonic]
            if bytecode_obj.registers is not None:
                instruction.extend(bytecode_obj.registers)
            if bytecode_obj.parameter is not None:
                instruction.append(bytecode_obj.parameter)

            # for the case of MUTF8String
            instruction = [str(x) for x in instruction]

            if instruction[0] in pyeval.eval.keys():
                pyeval.eval[instruction[0]](instruction)

        return pyeval.show_table()



