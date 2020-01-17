# This file is part of Quark Engine - https://quark-engine.rtfd.io
# See GPLv3 for copying permission.


class TableObject:
    """This table is used to track the usage of variables in the register"""

    def __init__(self, count_reg):
        """
        This table used to store the variable object, which uses a hash table
        with a stack-based list to generate the bytecode variable tracker table.

        :param count_reg: the maximum number of register to initialize
        """
        self.hash_table = [[] for _ in range(count_reg)]

    def __repr__(self):
        return "<TableObject-{}>".format(self.hash_table)

    def insert(self, index, var_obj):
        """
        Insert VariableObject into the nested list in the hashtable.

        :param index: the index to insert to the table
        :param var_obj: instance of VariableObject
        :return: None
        """
        self.hash_table[index].append(var_obj)

    def get_obj_list(self, index):
        """
        Return the list which contains the VariableObject.

        :param index: the index to get the corresponding VariableObject
        :return: a list containing VariableObject
        """
        return self.hash_table[index]

    def get_table(self):
        """
        Get the entire hash table.

        :return: a two-dimensional list
        """
        return self.hash_table

    def pop(self, index):
        """
        Override the built-in pop function, to get the top element, which
        is VariableObject on the stack while not delete it.

        :param index: the index to get the corresponding VariableObject
        :return: VariableObject
        """
        return self.hash_table[index][-1]


if __name__ == "__main__":
    pass
