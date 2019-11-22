class VarabileObject:
    """
    Data structure for creating the bytecode variable
    object.

    +================+========+==================+
    | register_name  | value | called_by_func   |
    +================+========+==================+
    """

    def __init__(self, register_name, value, called_by_func=None):
        """

        :param register_name:
        :param value:
        :param called_by_func:
        """
        self._register_name = register_name
        self._value = value
        self._called_by_func = []
        if called_by_func is not None:
            self._called_by_func.append(called_by_func)

    @property
    def called_by_func(self):
        """

        :return:
        """
        return self._called_by_func

    @called_by_func.setter
    def called_by_func(self, called_by_func):
        """

        :param called_by_func:
        :return:
        """
        self._called_by_func.append(called_by_func)

    @property
    def register_name(self):
        """

        :return:
        """
        return self._register_name

    @register_name.setter
    def register_name(self, reg_name):
        """

        :param reg_name:
        :return:
        """
        self._register_name = reg_name

    @property
    def value(self):
        """

        :return:
        """
        return self._value

    @value.setter
    def value(self, value):
        """

        :param value:
        :return:
        """
        self._value = value

    def get_all(self):
        """

        :return:
        """

        return f"{self._register_name} ,{self._value} ,[{','.join(self._called_by_func)}]"

    @property
    def hash_index(self):
        """

        :return:
        """
        return int(self.register_name[-1])


if __name__ == "__main__":
    pass
