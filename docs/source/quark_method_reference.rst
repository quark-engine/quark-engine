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

check_parameter_on_single_method
=======================================

**The algorithm of check_parameter_on_single_method**

The ``check_parameter_on_single_method`` function checks whether two methods use the same parameter.

Here is the process of ``check_parameter_on_single_method``.

.. code-block:: TEXT

    1. Define a method named check_parameter_on_single_method, which takes 5 parameters:
        * self: a reference to the current object, indicating that this method is defined in a class
        * usage_table: a table for storing the usage of called functions
        * first_method: the first API or the method calling the first API
        * second_method: the second API or the method calling the second API
        * keyword_item_list: a list of keywords used to determine if the parameter meets specific conditions

    2. Define a Boolean variable regex, which is set to False by default.

    3. Obtain the patterns of first_method and second_method based on the given input, and store them in 
    first_method_pattern and second_method_pattern, respectively.

    4. Define a generator matched_records. Use the filter function to filter register_usage_records to 
    include only those matched records used by both first_method and second_method.

    5. Use a for loop to process the matched records one by one.

    6. Call method check_parameter_values to check if the matched records contain keywords in keyword_item_list. 
        - If True, add matched keywords to matched_keyword_list.
        - If False, leave matched_keyword_list empty.

    7. Use yield to return the matched record and matched_keyword_list. This method is a generator that processes 
    data and returns results at the same time.

Here is the flowchart of ``check_parameter_on_single_method``.

.. image:: https://i.imgur.com/BJf7oSg.png

**The code of check_parameter_on_single_method**

.. code:: python

    def check_parameter_on_single_method(
        self,
        usage_table,
        first_method,
        second_method,
        keyword_item_list=None,
        regex=False,
    ) -> Generator[Tuple[str, List[str]], None, None]:
        """Check the usage of the same parameter between two method.

        :param usage_table: the usage of the involved registers
        :param first_method: the first API or the method calling the first APIs
        :param second_method: the second API or the method calling the second
         APIs
        :param keyword_item_list: keywords required to be present in the usage
         , defaults to None
        :param regex: treat the keywords as regular expressions, defaults to
         False
        :yield: _description_
        """
        first_method_pattern = PyEval.get_method_pattern(
            first_method.class_name, first_method.name, first_method.descriptor
        )

        second_method_pattern = PyEval.get_method_pattern(
            second_method.class_name,
            second_method.name,
            second_method.descriptor,
        )

        register_usage_records = (
            c_func
            for table in usage_table
            for val_obj in table
            for c_func in val_obj.called_by_func
        )

        matched_records = filter(
            lambda r: first_method_pattern in r and second_method_pattern in r,
            register_usage_records,
        )

        for record in matched_records:
            if keyword_item_list and list(keyword_item_list):
                matched_keyword_list = self.check_parameter_values(
                    record,
                    (first_method_pattern, second_method_pattern),
                    keyword_item_list,
                    regex,
                )

                if matched_keyword_list:
                    yield (record, matched_keyword_list)

            else:
                yield (record, None)

check_parameter
==================

**The algorithm of check_parameter**

The function ``check_parameter`` is designed to check for the usage of the same parameter between two methods.

Here is the process of ``check_parameter``.

.. code-block:: TEXT

    1. Check if parent_function, first_method_list or second_method_list is None. 
        - If True, raise a TypeError exception.

    2. Check if the keyword_item_list parameter exists and has elements.
        - If False, set keyword_item_list to None.

    3. Initialize the state variable to False.

    4. Evaluate the opcode of the parent_function by calling self._evaluate_method and store the result to usage_table. 

    5. Iterate through the combinations of methods from the first_method_list and second_method_list. 

    6. Call self.check_parameter_on_single_method with usage_table to check if the two methods use the same parameters. 
        - If True, 
            - Record the corresponding call graph analysis.
            - Record the mapping between the parent function and the wrapper method. 
            - Set the state variable to True.

    7. Once the iteration finishes, return the state variable.

Here is the flowchart of ``check_parameter``.

.. image:: https://i.imgur.com/Og1mXss.png

**The code of check_parameter**

.. code:: python

    def check_parameter(
        self,
        parent_function,
        first_method_list,
        second_method_list,
        keyword_item_list=None,
        regex=False,
    ):
        """
        Check the usage of the same parameter between two method.

        :param parent_function: function that call the first function and
         second functions at the same time.
        :param first_method_list: function which calls before the second
         method.
        :param second_method_list: function which calls after the first method.
        :return: True or False
        """
        if parent_function is None:
            raise TypeError("Parent function is None.")

        if first_method_list is None or second_method_list is None:
            raise TypeError("First or second method list is None.")

        if keyword_item_list:
            keyword_item_list = list(keyword_item_list)
            if not any(keyword_item_list):
                keyword_item_list = None

        state = False

        # Evaluate the opcode in the parent function
        usage_table = self._evaluate_method(parent_function)

        # Check if any of the target methods (the first and second methods)
        #  used the same registers.
        state = False
        for first_call_method in first_method_list:
            for second_call_method in second_method_list:

                result_generator = self.check_parameter_on_single_method(
                    usage_table,
                    first_call_method,
                    second_call_method,
                    keyword_item_list,
                    regex,
                )

                found = next(result_generator, None) is not None

                # Build for the call graph
                if found:
                    call_graph_analysis = {
                        "parent": parent_function,
                        "first_call": first_call_method,
                        "second_call": second_call_method,
                        "apkinfo": self.apkinfo,
                        "first_api": self.quark_analysis.first_api,
                        "second_api": self.quark_analysis.second_api,
                        "crime": self.quark_analysis.crime_description,
                    }
                    self.quark_analysis.call_graph_analysis_list.append(
                        call_graph_analysis
                    )

                    # Record the mapping between the parent function and the
                    #  wrapper method
                    self.quark_analysis.parent_wrapper_mapping[
                        parent_function.full_name
                    ] = self.apkinfo.get_wrapper_smali(
                        parent_function,
                        first_call_method,
                        second_call_method,
                    )

                    state = True

        return state

check_parameter_values
==========================

**The algorithm of check_parameter_values**

The function ``check_parameter_values`` is designed to check if the parameter values in the source string match the specified patterns and keywords. Then it collects the matched strings into a set and return it.

Here is the process of ``check_parameter_values``.

.. code-block:: TEXT

    1. Create an empty set matched_string_set.

    2. Use tools.get_parenthetic_contents to extract the content that matches each pattern in the pattern_list from the source_str. Store the results in the parameter_strs list.

    3. Use zip to pair up the parameter_strs and keyword_item_list and iterate over them.

    4. For each pairing of parameter_str and keyword_item, perform the following operations:
        - Check if keyword_item is not None.
            - For each keyword in keyword_item, perform the following operations:
                - Check If regex is True, 
                    - If True, 
                        - Use re.findall to search for matching strings and store them in matched_strings.
                        - Check if matched_strings has any matching strings.
                            - If True, Add all nonempty strings from matched_strings to the matched_string_set. 
                    - If False, add all keywords in parameter_str to the matched_string_set.
        
    5.  Once the iteration finishes, return a list of strings from the matched_string_set, which represents all the matched results.


Here is the flowchart of ``check_parameter_values``.

.. image:: https://i.imgur.com/SiMGE2w.png

**The code of check_parameter_values**

.. code:: python

    @staticmethod
    def check_parameter_values(
        source_str, pattern_list, keyword_item_list, regex=False
    ) -> List[str]:
        matched_string_set = set()

        parameter_strs = [
            tools.get_parenthetic_contents(
                source_str, source_str.index(pattern) + len(pattern)
            )
            for pattern in pattern_list
        ]

        for parameter_str, keyword_item in zip(
            parameter_strs, keyword_item_list
        ):
            if keyword_item is None:
                continue

            for keyword in keyword_item:
                if regex:
                    matched_strings = re.findall(keyword, parameter_str)
                    if any(matched_strings):
                        matched_strings = filter(bool, matched_strings)
                        matched_strings = list(matched_strings)

                        element = matched_strings[0]
                        if isinstance(
                            element, collections.abc.Sequence
                        ) and not isinstance(element, str):
                            for str_list in matched_strings:
                                matched_string_set.update(str_list)

                        else:
                            matched_string_set.update(matched_strings)

                else:
                    if str(keyword) in parameter_str:
                        matched_string_set.add(keyword)

        return [e for e in list(matched_string_set) if bool(e)]



check_sequence
===============

**The algorithm of check_sequence**

The function ``check_sequence`` checks if ``mutual_parent`` calls any first method before any second method. If Yes, ``check_sequence`` records the mapping between ``mutual_parent`` and the matched methods and returns True.

Here is the process of ``check_sequence``.


.. code-block:: TEXT

    1. Initialize the variable state as False.

    2. Iterate the method pairs formed by first_method_list and second_method_list.

    3. From mutual_parent, find method calls that call any method in the pair. Then collect them into the list seq_table.

    4. Check if the length of seq_table is less than 2.
        - If True, continue to the next iteration.
        
    5. Sort seq_table according to the offsets of the method calls. Then name the sorted list as method_list_need_check.

    6. Check if the method pair is a sublist of method_list_need_check.
        - If True, 
            - Set state to True.
            - Record the mapping between mutual_parent and the method pair in quark_analysis.
            
    7. Return state.

Here is the flowchart of ``check_sequence``.

.. image:: https://i.imgur.com/8wmEre6.png 

**The code of check_sequence**


.. code:: python

   def check_sequence(
        self, mutual_parent, first_method_list, second_method_list
    ):
        """
        Check if the first function appeared before the second function.

        :param mutual_parent: function that call the first function and second functions at the same time.
        :param first_method_list: the first show up function, which is a MethodAnalysis
        :param second_method_list: the second show up function, which is a MethodAnalysis
        :return: True or False
        """
        state = False

        for first_call_method in first_method_list:
            for second_call_method in second_method_list:

                seq_table = [
                    (call, number)
                    for call, number in self.apkinfo.lowerfunc(mutual_parent)
                    if call in (first_call_method, second_call_method)
                ]

                # sorting based on the value of the number
                if len(seq_table) < 2:
                    # Not Found sequence in same_method
                    continue
                seq_table.sort(key=operator.itemgetter(1))
                # seq_table would look like: [(getLocation, 1256), (sendSms, 1566), (sendSms, 2398)]

                method_list_need_check = [x[0] for x in seq_table]
                sequence_pattern_method = [
                    first_call_method,
                    second_call_method,
                ]

                if tools.contains(
                    sequence_pattern_method, method_list_need_check
                ):
                    state = True

                    # Record the mapping between the parent function and the wrapper method
                    self.quark_analysis.parent_wrapper_mapping[
                        mutual_parent.full_name
                    ] = self.apkinfo.get_wrapper_smali(
                        mutual_parent, first_call_method, second_call_method
                    )

        return state



run
===============

**The algorithm of run**

The function ``run`` checks the APK file at five levels to analyze whether it meets the rules. 

Here is the process of ``run``.

.. code-block:: TEXT

    1. Clean the results of the previous analysis.

    2. Store the 'crime' description in the analysis result
    
    3. Level 1 Check: Permission requested
        - Check if the input file is a DEX file. 
            - If Yes, set the first item of check_item in rule_obj to True.
            - If No, check if the permissions of the APK include the permissions in the rule. 
                - If Yes, set the first item of check_item to True.
                - If No, the function exits.

    4. Level 2 Check: Native API call
        - Check if the APK uses any of the two native APIs in the rule.
            - If Yes, set the second item of check_item to True and store information about the calls of the two native APIs in the analysis result.
            - If No, the function exits.

    5. Level 3 Check: Certain combination of native API
	    - Check if the APK uses both native APIs in the rule.
	        - If Yes, set the third item of check_item to True and store the calls of the two native APIs in the analysis result.
            - If No, the function exits.

    6. Level 4 Check: Calling sequence of native API
        - Check if there are any mutual parent functions between each combined API call of the two native APIs
            - If Yes, check if any mutual parent function calls the first method before the second method.
                    - If Yes, set the fourth item of check_item to True and store information about the parent functions in the analysis result.
            - If No, the function exits.

    7. Level 5 Check: APIs that handle the same register
        - Check if the native APIs in the rule handle the same registers.
            - If Yes, set the fifth item of check_item to True and store the parent functions in the analysis result.
            - If No, the function exits.



Here is the flowchart of ``run``.

.. image:: https://i.imgur.com/v152g3L.png

**The code of run**


.. code:: python

    def run(self, rule_obj):
        """
        Run the five levels check to get the y_score.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        self.quark_analysis.clean_result()
        self.quark_analysis.crime_description = rule_obj.crime

        # Level 1: Permission Check
        if self.apkinfo.ret_type == "DEX":
            rule_obj.check_item[0] = True
        elif set(rule_obj.permission).issubset(set(self.apkinfo.permissions)):
            rule_obj.check_item[0] = True
        else:
            # Exit if the level 1 stage check fails.
            return

        # Level 2: Single Native API Check
        api_1_method_name = rule_obj.api[0]["method"]
        api_1_class_name = rule_obj.api[0]["class"]
        api_1_descriptor = rule_obj.api[0]["descriptor"]

        api_2_method_name = rule_obj.api[1]["method"]
        api_2_class_name = rule_obj.api[1]["class"]
        api_2_descriptor = rule_obj.api[1]["descriptor"]

        first_api_list = self.find_api_usage(
            api_1_class_name, api_1_method_name, api_1_descriptor
        )
        second_api_list = self.find_api_usage(
            api_2_class_name, api_2_method_name, api_2_descriptor
        )

        if not first_api_list and not second_api_list:
            # Exit if the level 2 stage check fails.
            return

        else:
            rule_obj.check_item[1] = True

        if first_api_list:
            self.quark_analysis.level_2_result.append(first_api_list[0])
        if second_api_list:
            self.quark_analysis.level_2_result.append(second_api_list[0])

        # Level 3: Both Native API Check
        if not (first_api_list and second_api_list):
            # Exit if the level 3 stage check fails.
            return

        self.quark_analysis.first_api = first_api_list[0]
        self.quark_analysis.second_api = second_api_list[0]
        rule_obj.check_item[2] = True

        self.quark_analysis.level_3_result = [set(), set()]

        # Level 4: Sequence Check
        for first_api in first_api_list:
            for second_api in second_api_list:
                # Looking for the first layer of the upper function
                first_api_xref_from = self.apkinfo.upperfunc(first_api)
                second_api_xref_from = self.apkinfo.upperfunc(second_api)

                self.quark_analysis.level_3_result[0].update(
                    first_api_xref_from
                )
                self.quark_analysis.level_3_result[1].update(
                    second_api_xref_from
                )

                if not first_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of {first_api}"
                    )
                    continue
                if not second_api_xref_from:
                    print_warning(
                        f"Unable to find the upperfunc of{second_api}"
                    )
                    continue

                mutual_parent_function_list = self.find_intersection(
                    first_api_xref_from, second_api_xref_from
                )

                if mutual_parent_function_list is None:
                    # Exit if the level 4 stage check fails.
                    return
                for parent_function in mutual_parent_function_list:
                    first_wrapper = []
                    second_wrapper = []

                    self.find_previous_method(
                        first_api, parent_function, first_wrapper
                    )
                    self.find_previous_method(
                        second_api, parent_function, second_wrapper
                    )

                    if self.check_sequence(
                        parent_function, first_wrapper, second_wrapper
                    ):
                        rule_obj.check_item[3] = True
                        self.quark_analysis.level_4_result.append(
                            parent_function
                        )

                        keyword_item_list = (
                            rule_obj.api[i].get("keyword", None)
                            for i in range(2)
                        )

                        # Level 5: Handling The Same Register Check
                        if self.check_parameter(
                            parent_function,
                            first_wrapper,
                            second_wrapper,
                            keyword_item_list=keyword_item_list,
                        ):
                            rule_obj.check_item[4] = True
                            self.quark_analysis.level_5_result.append(
                                parent_function
                            )


get_json_report
===============

**The algorithm of get_json_report**

The function ``get_json_report`` generates a report of the analysis performed on the APK file, in JSON format.

Here is the process of ``get_json_report``.


.. code-block:: TEXT

    1. Create a Weight object with the total score and weight from the analysis result.

    2. Calculate the threat level with the Weight object and store the result in the variable warning.

    3. Loop through a list of threat levels and check if the variable warning contains any of the threat levels.
        - If Yes, sets the variable warning to the threat level.
 
    4. Return a report with various pieces of information:
        - The MD5 hash of the APK
        - The filename of the APK
        - The file size of the APK
        - The threat level of the APK
        - The total score of the analysis result
        - The JSON report of the analysis result


Here is the flowchart of ``get_json_report``.

.. image:: https://i.imgur.com/i2JZJQ0.png


**The code of get_json_report**


.. code:: python

   def get_json_report(self):
        """
        Get quark report including summary and detail with json format.

        :return: json report
        """

        w = Weight(
            self.quark_analysis.score_sum, self.quark_analysis.weight_sum
        )
        warning = w.calculate()

        # Filter out color code in threat level
        for level in ["Low Risk", "Moderate Risk", "High Risk"]:
            if level in warning:
                warning = level

        return {
            "md5": self.apkinfo.md5,
            "apk_filename": self.apkinfo.filename,
            "size_bytes": self.apkinfo.filesize,
            "threat_level": warning,
            "total_score": self.quark_analysis.score_sum,
            "crimes": self.quark_analysis.json_report,
        }


generate_json_report
===============

**The algorithm of generate_json_report**

The function ``‎generate_json_report`` generates a JSON report based on the information extracted from the ruleobject instance .

Here is the process of ``generate_json_report``.


.. code-block:: TEXT

    1. Calculate confidence percentage by counting the number of True values in check_item and multiplying by 20. Store the confidence value.

    2. Count the True values in check_item and store the count as conf. Use conf to calculate the weight of the rule using the get_score method.

    3. Assign the score attribute's value to the score variable.

    4. Check the first item in check_item.
        -If True, assign the permission attribute to permissions.
        -Otherwise, assign an empty list.

    5. Check the second item in check_item.
        -If True, populate the API list with dictionaries from quark_analysis.level_2_result.

    6. Check the third item in check_item.
        -If True, assign the API attribute's value to the combination variable.

    7. Define two empty lists: 
        -sequnce_show_up
        -same_operation_show_up

    8. Check if the fourth item in the check_item is True and the quark_analysis.level_4_result list is not empty. 
        -If True, 
            -populate the sequnce_show_up list with dictionaries containing full_name attributes and their corresponding values from quark_analysis.parent_wrapper_mapping.
            -Check if the fifth item in the check_item is True and the quark_analysis.level_5_result list is not empty.
                -If True, populate the same_operation_show_up list with dictionaries containing full_name attributes and their corresponding values from quark_analysis.parent_wrapper_mapping.

    9. Create a dictionary called crime, containing the following attributes:	
        -rule：filename of rule in rule_obj
        -crime：description of quark_analysis's crime in rule_obj
        -label：the label in rule_obj
        -score：the score in rule_obj
        -weight：the weight in rule_obj
        -confidence：the number of True values in check_item and multiplying by 20
        -permissions：the permission in rule_obj
        -native_api：list with dictionaries from quark_analysis.level_2_result
        -combination：the value of the api attribute of rule_obj
        -sequence：sequnce_show_up, information about the items in quark_analysis.level_4_result
        -register：same_operation_show_up, information about the items in the quark_analysis.level_5_result

    10. Append the crime dictionary to the json_report attribute of quark_analysis.

    11. Add the weight to the weight_sum attribute of quark_analysis.

    12. Add the score to the score_sum attribute of quark_analysis.



Here is the flowchart of ``generate_json_report``.

.. image:: https://i.imgur.com/gROkCdB.png


**The code of generate_json_report**


.. code:: python

   def generate_json_report(self, rule_obj):
        """
        Show the json report.

        :param rule_obj: the instance of the RuleObject
        :return: None
        """
        # Count the confidence
        confidence = str(rule_obj.check_item.count(True) * 20) + "%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.score

        # Assign level 1 examine result
        permissions = rule_obj.permission if rule_obj.check_item[0] else []

        # Assign level 2 examine result
        api = []
        if rule_obj.check_item[1]:
            for item2 in self.quark_analysis.level_2_result:
                api.append(
                    {
                        "class": str(item2.class_name),
                        "method": str(item2.name),
                        "descriptor": str(item2.descriptor),
                    }
                )

        # Assign level 3 examine result
        combination = []
        if rule_obj.check_item[2]:
            combination = rule_obj.api

        # Assign level 4 - 5 examine result if exist
        sequnce_show_up = []
        same_operation_show_up = []

        # Check examination has passed level 4
        if self.quark_analysis.level_4_result and rule_obj.check_item[3]:
            for item4 in self.quark_analysis.level_4_result:
                sequnce_show_up.append(
                    {
                        item4.full_name: self.quark_analysis.parent_wrapper_mapping[
                            item4.full_name
                        ]
                    }
                )

            # Check examination has passed level 5
            if self.quark_analysis.level_5_result and rule_obj.check_item[4]:
                for item5 in self.quark_analysis.level_5_result:
                    same_operation_show_up.append(
                        {
                            item5.full_name: self.quark_analysis.parent_wrapper_mapping[
                                item5.full_name
                            ]
                        }
                    )

        crime = {
            "rule": rule_obj.rule_filename,
            "crime": rule_obj.crime,
            "label": rule_obj.label,
            "score": score,
            "weight": weight,
            "confidence": confidence,
            "permissions": permissions,
            "native_api": api,
            "combination": combination,
            "sequence": sequnce_show_up,
            "register": same_operation_show_up,
        }
        self.quark_analysis.json_report.append(crime)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score


add_table_row
===============

**The algorithm of add_table_row**

The function ``add_table_row`` adds a list to the table.

Here is the process of ``add_table_row``.


.. code-block:: TEXT

    1. The method add_row is then called with a list of parameters. This list includes:
        name: filename of rule in rule_obj
        rule_obj.crime: description of quark_analysis's crime in rule_obj
        confidence: the number of True values in check_item and multiplying by 20
        score: the score in rule_obj
        weight: the weight in rule_obj

    2. The add_row method takes these parameters and adds them as a new row in the summary_report_table.

Here is the flowchart of ``add_table_row``.

.. image:: https://i.imgur.com/5YEubbB.png


**The code of add_table_row**


.. code:: python

    def add_table_row(self, name, rule_obj, confidence, score, weight):

        self.quark_analysis.summary_report_table.add_row(
            [
                name,
                green(rule_obj.crime),
                yellow(confidence),
                score,
                red(weight),
            ]
        )

show_summary_report
===============

**The algorithm of show_summary_report**

The function ``show_summary_report`` generates a summary report.

Here is the process of ``show_summary_report``.


.. code-block:: TEXT

    1. Calculate confidence by counting occurrences of True in rule_obj.check_item and multiplying it by 20 to get a percentage.

    2. Calculate the weight using the confidence value through rule_obj.get_score, and retrieves score and rule_filename from rule_obj.

    3. Check if a threshold is provided.
        -If true, check if the confidence percentage is greater than or equal to the threshold.
            -If true, calls add_table_row with relevant arguments.
        -If false, calls add_table_row with relevant arguments.

    4. Update the quark_analysis instance by adding the calculated weight and score to weight_sum and score_sum.

Here is the flowchart of ``show_summary_report``.

.. image:: https://i.imgur.com/0B3nYsa.png


**The code of show_summary_report**


.. code:: python

    def show_summary_report(self, rule_obj, threshold=None):
        """
        Show the summary report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """
        # Count the confidence
        confidence = f"{rule_obj.check_item.count(True) * 20}%"
        conf = rule_obj.check_item.count(True)
        weight = rule_obj.get_score(conf)
        score = rule_obj.score
        name = rule_obj.rule_filename

        if threshold:

            if rule_obj.check_item.count(True) * 20 >= int(threshold):
                self.add_table_row(name, rule_obj, confidence, score, weight)

        else:
            self.add_table_row(name, rule_obj, confidence, score, weight)

        # add the weight
        self.quark_analysis.weight_sum += weight
        # add the score
        self.quark_analysis.score_sum += score

show_label_report
==================

**The algorithm of show_label_report**

The function ``show_label_report`` generates a tabular report that summarizes statistical information.

Here is the process of ``show_label_report``.

.. code-block:: TEXT

    1. Clear label_report_table and initializes label_desc.

    2. Iterate through the all_labels dictionary.

    3. Calculate the maximum, average, and standard deviation of the confidence values for each label.

    4. Check if table_version is max.
	- If true, set table header for table_version is max.
	- If false, set table header for table_version is not max.

Here is the flowchart of ``show_label_report``.

.. image:: https://i.imgur.com/uT0RuB8.png


**The code of show_label_report**


.. code:: python

    def show_label_report(self, rule_path, all_labels, table_version):
        """
        Show the report based on label, last column represents max confidence for that label
        :param rule_path: the path where may be present the file label_desc.csv.
        :param all_labels: dictionary containing label:<array of confidence values associated to that label>
        :return: None
        """
        label_desc = {}
        # clear table to manage max/detail version
        self.quark_analysis.label_report_table.clear()
        if os.path.isfile(os.path.join(rule_path, "label_desc.csv")):
            # associate to each label a description
            col_list = ["label", "description"]
            # csv file on form <label,description>
            # put this file in the folder of rules (it must not be a json file since it could create conflict with management of rules)
            # remove temporarily
            #df = pd.read_csv(
            #    os.path.join(rule_path, "label_desc.csv"), usecols=col_list
            #)
            #
            #label_desc = dict(zip(df["label"], df["description"]))

        for label_name in all_labels:
            confidences = np.array(all_labels[label_name])

            if table_version == "max":
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                    ]
                )
            else:
                self.quark_analysis.label_report_table.field_names = [
                    "Label",
                    "Description",
                    "Number of rules",
                    "MAX Confidence %",
                    "AVG Confidence",
                    "Std Deviation",
                    "# of Rules with Confidence >= 80%",
                ]
                self.quark_analysis.label_report_table.add_row(
                    [
                        green(label_name),
                        yellow(label_desc.get(label_name, "-")),
                        (len(confidences)),
                        red(np.max(confidences)),
                        magenta(round(np.mean(confidences), 2)),
                        lightblue(round(np.std(confidences), 2)),
                        lightyellow(np.count_nonzero(confidences >= 80)),
                    ]
                )


show_detail_report
==================

**The algorithm of show_detail_report**

The function ``show_detail_report`` prints a report summarizing the result of the five-level check and the confidence of the APK.

Here is the process of ``show_detail_report``.

.. code-block:: TEXT

    1. Calculate the confidence of the APK by multiplying the number of passed levels by 20.

    2. Check if the APK passed level 1.
        - If passed, show the match permissions.

    3. Check if the APK passed level 2.
        - If passed, show the matched APIs.

    4. Check if the APK passed level 3.
        - If passed, show the matched API combinations.
        
    5. Check if the APK passed level 4.
        - If passed, show the matched API sequences.
        
    6. Check if the APK passed level 5.
        - If passed, show the matched API sequences that use the same register.

Here is the flowchart of ``show_detail_report``.

.. image:: https://i.imgur.com/s1DZVHs.png


**The code of show_detail_report**


.. code:: python

    def show_detail_report(self, rule_obj):
        """
        Show the detail report.

        :param rule_obj: the instance of the RuleObject.
        :return: None
        """

        # Count the confidence
        print("")
        print(f"Confidence: {rule_obj.check_item.count(True) * 20}%")
        print("")

        if rule_obj.check_item[0]:

            colorful_report("1.Permission Request")
            for permission in rule_obj.permission:
                print(f"\t\t {permission}")
        if rule_obj.check_item[1]:
            colorful_report("2.Native API Usage")
            for api in self.quark_analysis.level_2_result:
                print(f"\t\t {api.full_name}")
        if rule_obj.check_item[2]:
            colorful_report("3.Native API Combination")
            for numbered_api, method_list in zip(
                ("First API", "Second API"), self.quark_analysis.level_3_result
            ):
                print(f"\t\t {numbered_api} show up in:")
                if method_list:
                    for comb_method in method_list:
                        print(f"\t\t {comb_method.full_name}")
                else:
                    print("\t\t None")

        if rule_obj.check_item[3]:

            colorful_report("4.Native API Sequence")
            print("\t\t Sequence show up in:")
            for seq_method in self.quark_analysis.level_4_result:
                print(f"\t\t {seq_method.full_name}")
        if rule_obj.check_item[4]:

            colorful_report("5.Native API Use Same Parameter")
            for seq_operation in self.quark_analysis.level_5_result:
                print(f"\t\t {seq_operation.full_name}")

show_call_graph
==================

**The algorithm of show_call_graph**

The function ``show_call_graph`` creates a call graph for each element in call_graph_analysis_list and displays messages to indicate progress.

Here is the process of ``show_call_graph``.

.. code-block:: TEXT

    1. Display the message "Creating Call Graph..." in cyan color.

    2. Create a call graph for each element in call_graph_analysis_list.

    3. Display the message "Call Graph Completed" in green color.



Here is the flowchart of ``show_call_graph``.

.. image:: https://i.imgur.com/18pGB7w.png



**The code of show_call_graph**


.. code-block:: python

    def show_call_graph(self, output_format=None):
        print_info("Creating Call Graph...")
        for (
            call_graph_analysis
        ) in self.quark_analysis.call_graph_analysis_list:
            call_graph(call_graph_analysis, output_format)
        print_success("Call Graph Completed")


show_rule_classification
===============================

**The algorithm of show_rule_classification**

The function ``show_rule_classification`` display rule classification information by fetching relevant data and then outputting it in table, JSON, and graphical formats.

Here is the process of ``show_rule_classification``.

.. code-block:: TEXT

	1. Call the print_info function to display the "Rules Classification".

	2. Invoke the get_rule_classification_data function
		- Using self.quark_analysis.call_graph_analysis_list and MAX_SEARCH_LAYER as parameters.
		- Store the returned rule classification data in the data_bundle variable.

	3. Call the output_parent_function_table function to display tables on the console. 
        	- The first column of the table is "Parent Function", and the second column displays the name of that parent function. 
        	- Subsequent rows list the "Crime Description" associated with that parent function.
   
    	4. Call the output_parent_function_json function output a JSON file named "rules_classification.json".
        	- The structure of the file is a list containing multiple dictionaries. Each dictionary has two keys: parent and crime. 
 
    	5. Call the output_parent_function_graph function create a PNG format graphic file.
        	- This graphic displays the reference relationships between parent functions and the crime descriptions associated with each parent function.


Here is the flowchart of ``show_rule_classification``.

.. image:: https://i.imgur.com/dULiqhS.png

**The code of show_rule_classification**

.. code-block:: python

    def show_rule_classification(self):
        print_info("Rules Classification")

        data_bundle = get_rule_classification_data(
            self.quark_analysis.call_graph_analysis_list, MAX_SEARCH_LAYER
        )

        output_parent_function_table(data_bundle)
        output_parent_function_json(data_bundle)
        output_parent_function_graph(data_bundle)
