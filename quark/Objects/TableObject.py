class TableObject:
    """
    This table used to store the variable object,
    which using a hash table with a stack-based
    list to generate the bytecode variable tracker table.
    """

    def __init__(self, count_reg):
        """

        :param count_reg:
        """
        self.hash_table = [[] for _ in range(count_reg)]

    def insert(self, index, var_obj):
        """
        insert VariableObject into the nested
        list in the hashtable.
        :param index:
        :param var_obj:
        :return:
        """
        self.hash_table[index].append(var_obj)

    def get_obj_list(self, index):
        """
        return the list which contains the
        VariableObject.
        :param index:
        :return:
        """
        return self.hash_table[index]

    def get_table(self):
        """
        :rtype: list
        :return: a nested list.
        """
        return self.hash_table

    def pop(self, index):
        """
        override the original pop() to `not`
        deleting element after() in order to get
        the top element of the stack in the
        hashtable, which is VariableObject.

        :rtype: VariableObject
        """
        return self.hash_table[index][-1]


if __name__ == "__main__":
    pass
