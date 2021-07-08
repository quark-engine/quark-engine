# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.


class RegisterObject:
    """The RegisterObject is used to record the state of each register"""

    __slots__ = ["_register_name", "_value", "_called_by_func"]

    def __init__(self, register_name, value, called_by_func=None):
        """
        A data structure for creating the bytecode variable object, which
        used to record the state of each register.

        +================+========+==================+
        | register_name  | value | called_by_func    |
        +================+========+==================+

        :param register_name:
        :param value:
        :param called_by_func:
        """
        self._register_name = register_name
        self._value = value
        self._called_by_func = []
        if called_by_func is not None:
            self._called_by_func.append(called_by_func)

    def __repr__(self):
        return f"<VarabileObject-register:{self._register_name}, value:{self._value}, called_by_func:{','.join(self._called_by_func)}>"

    @property
    def called_by_func(self):
        """
        Record which functions have been called by using this register as a parameter.

        :return: a list containing function name
        """
        return self._called_by_func

    @called_by_func.setter
    def called_by_func(self, called_by_func):
        """
        Setter of called_by_func.

        :param called_by_func:
        :return: None
        """
        self._called_by_func.append(called_by_func)

    @property
    def register_name(self):
        """
        Individual register name, for example 'v3'.

        :return: a string of register name
        """
        return self._register_name

    @register_name.setter
    def register_name(self, reg_name):
        """
        Setter of register_name.

        :param reg_name:
        :return: None
        """
        self._register_name = reg_name

    @property
    def value(self):
        """
        The current value stored in the register.

        :return: a string of the value
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Setter of value.

        :param value:
        :return: None
        """
        self._value = value

    @property
    def hash_index(self):
        """
        Get the index number from given VarabileObject.

        :return: an integer corresponding to the register index
        """
        return int(self.register_name[1:])


if __name__ == "__main__":
    pass
