# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
# Thanks for the description of Dalvik bytecode instruction from the following
# websites, some of our explanations or comments will quote from it.
# https://source.android.google.cn/devices/tech/dalvik/instruction-formats
# http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

import logging
from datetime import datetime

from quark.Objects.struct.registerobject import RegisterObject
from quark.Objects.struct.tableobject import TableObject

MAX_REG_COUNT = 40
TIMESTAMPS = datetime.now().strftime('%Y-%m-%d')
LOG_FILENAME = f"{TIMESTAMPS}.quark.log"
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME, mode='w')
format_str = '%(asctime)s %(levelname)s [%(lineno)d]: %(message)s'
handler.setFormatter(logging.Formatter(format_str))
log.addHandler(handler)


def logger(func):
    def warp(*args, **kwargs):
        log.info(f"{func.__name__} with args-> {args}")

        func(*args, **kwargs)

    return warp


class PyEval:
    def __init__(self):
        # Main switch for executing the bytecode instruction.
        self.eval = {
            # invoke-kind
            "invoke-virtual": self.INVOKE_VIRTUAL,
            "invoke-direct": self.INVOKE_DIRECT,
            "invoke-static": self.INVOKE_STATIC,
            "invoke-virtual/range": self.INVOKE_VIRTUAL_RANGE,
            "invoke-interface": self.INVOKE_INTERFACE,
            "invoke-polymorphic": self.INVOKE_POLYMORPHIC,
            "invoke-custom": self.INVOKE_CUSTOM,
            # move-result-kind
            "move-result": self.MOVE_RESULT,
            "move-result-wide": self.MOVE_RESULT_WIDE,
            "move-result-object": self.MOVE_RESULT_OBJECT,
            # instance-kind
            "new-instance": self.NEW_INSTANCE,
            # const-kind
            "const-string": self.CONST_STRING,
            "const-string/jumbo": self.CONST_STRING,
            "const-class": self.CONST,
            "const": self.CONST,
            "const/4": self.CONST_FOUR,
            "const/16": self.CONST_SIXTEEN,
            "const/high16": self.CONST_HIGHSIXTEEN,
            "const-wide": self.CONST_WIDE,
            "const-wide/16": self.CONST_WIDE_SIXTEEN,
            "const-wide/32": self.CONST_WIDE_THIRTY_TWO,
            "const-wide/high16": self.CONST_WIDE_HIGHSIXTEEN,
            # array
            "aget-object": self.AGET_KIND,
        }

        # move-kind
        for prefix in ("move", "move-object", "move-wide"):
            for postfix in ("", "/from16", "/16"):
                self.eval[f"{prefix}{postfix}"] = self.MOVE_KIND
        self.eval["array-length"] = self.MOVE_KIND

        self.table_obj = TableObject(MAX_REG_COUNT)
        self.ret_stack = []

    def _invoke(self, instruction):
        """
        Function call in Android smali code. It will check if the corresponding table field has a value, if it does,
        inserts its own function name into called_by_func column.
        """

        executed_fuc = instruction[-1]
        reg_list = instruction[1: len(instruction) - 1]
        value_of_reg_list = []

        # query the value from hash table based on register index.
        for reg in reg_list:
            index = int(reg[1:])
            obj_stack = self.table_obj.get_obj_list(index)
            if obj_stack:
                var_obj = self.table_obj.pop(index)
                value_of_reg_list.append(var_obj.value)

        # insert the function and the parameter into called_by_func
        for reg in reg_list:
            index = int(reg[1:])
            obj_stack = self.table_obj.get_obj_list(index)
            if obj_stack:
                # add the function name into each parameter table
                var_obj = self.table_obj.pop(index)
                var_obj.called_by_func = f"{executed_fuc}({','.join(value_of_reg_list)})"

        # push the return value into ret_stack
        self.ret_stack.append(f"{executed_fuc}({','.join(value_of_reg_list)})")

    def _move_result(self, instruction):

        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = RegisterObject(reg, pre_ret)
            self.table_obj.insert(index, variable_object)
        except IndexError as e:

            log.exception(f"{e} in _move_result")

    def _assign_value(self, instruction):

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = RegisterObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def _assign_value_wide(self, instruction):
        """
        For 64 bit, it has two register, which is vx and vx+1
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])
        reg_plus_one = f"v{index + 1}"

        variable_object = RegisterObject(reg, value)
        variable_object2 = RegisterObject(reg_plus_one, value)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    @logger
    def INVOKE_VIRTUAL(self, instruction):
        """
        invoke-virtual { parameters }, methodtocall

        Invokes a virtual method with parameters.
        """
        self._invoke(instruction)

    @logger
    def INVOKE_DIRECT(self, instruction):
        """
        invoke-direct { parameters }, methodtocall

        Invokes a method with parameters without the virtual method resolution. (first parameter is "this")
        """
        self._invoke(instruction)

    @logger
    def INVOKE_STATIC(self, instruction):
        """
        invoke-static {parameters}, methodtocall

        Invokes a static method with parameters.
        """
        self._invoke(instruction)

    @logger
    def INVOKE_VIRTUAL_RANGE(self, instruction):
        """
        invoke-virtual/range { parameters }, methodtocall
        Invokes a virtual-range method with parameters.
        """
        self._invoke(instruction)

    @logger
    def INVOKE_INTERFACE(self, instruction):
        """
        invoke-interface { parameters }, methodtocall
        Invokes a interface method with parameters.
        """
        self._invoke(instruction)

    def INVOKE_POLYMORPHIC(self, instruction):
        self._invoke(instruction)

    def INVOKE_CUSTOM(self, instruction):
        self._invoke(instruction)

    @logger
    def MOVE_RESULT(self, instruction):
        """
        move-result vx

        Move the result value of the previous method invocation into vx.

        Save the value returned by the previous function call to the vx register,and then insert the VariableObject
        into table.
        """
        self._move_result(instruction)

    @logger
    def MOVE_RESULT_WIDE(self, instruction):
        """
        move-result-wide vx

        Move the long/double result value of the previous method invocation into vx,vx+1.
        """
        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = RegisterObject(reg, pre_ret)
            variable_object2 = RegisterObject(f"v{index + 1}", pre_ret)
            self.table_obj.insert(index, variable_object)
            self.table_obj.insert(index + 1, variable_object2)
        except IndexError as e:
            log.exception(f"{e} in MOVE_RESULT_WIDE")

    @logger
    def MOVE_RESULT_OBJECT(self, instruction):
        """
        move-result-object vx

        Move the result object reference of the previous method invocation into vx.

        Save the value returned by the previous function call to the vx register,and then insert the VariableObject
        into table.
        """

        self._move_result(instruction)

    @logger
    def NEW_INSTANCE(self, instruction):
        """
        new-instance vx,type

        Instantiates an object type and puts the reference of the newly created instance into vx.

        Store variables to vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction)

    @logger
    def CONST_STRING(self, instruction):
        """
        const-string vx,string_id

        Puts reference to a string constant identified by string_id into vx.

        Store string variable to vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction)

    @logger
    def CONST(self, instruction):
        """
        const vx, lit32

        Puts the integer constant into vx.
        """
        self._assign_value(instruction)

    @logger
    def CONST_FOUR(self, instruction):
        """
        const/4 vx,lit4

        Puts the 4 bit constant into vx.

        Store 4 bit constant into vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction)

    @logger
    def CONST_SIXTEEN(self, instruction):
        """
        const/16 vx,lit16

        Puts the 4 bit constant into vx.
        """
        self._assign_value(instruction)

    @logger
    def CONST_HIGHSIXTEEN(self, instruction):
        """
        const/high16 v0, lit16

        Puts the 16 bit constant into the topmost bits of the register. Used to initialize float values.
        """

        self._assign_value(instruction)

    @logger
    def CONST_WIDE(self, instruction):
        """
        const-wide vx, lit64

        Puts the 64 bit constant into vx and vx+1 registers.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_SIXTEEN(self, instruction):
        """
        const-wide/16 vx, lit16

        Puts the integer constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_THIRTY_TWO(self, instruction):
        """
        const-wide/32 vx, lit32

        Puts the 32 bit constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_HIGHSIXTEEN(self, instruction):
        """
        const-wide/high16 vx,lit16

        Puts the 16 bit constant into the highest 16 bit of vx and vx+1 registers. Used to initialize double values.
        """
        self._assign_value_wide(instruction)

    @logger
    def AGET_KIND(self, instruction):
        """
        aget-kind vx,vy,vz

        Gets an object reference value of an object reference array into vx. The array is referenced by vy and is
        indexed by vz.

        It means vx = vy[vz].
        """

    @logger
    def MOVE_KIND(self, instruction):
        try:
            wide = "wide" in instruction[0]
            self._move_value_to_register(instruction, "{src0}", wide=wide)
        except IndexError as e:
            log.exception(f"{e} in MOVE_KIND")


        try:

            array_obj = self.table_obj.get_obj_list(
                int(re.sub("[^0-9]", "", instruction[2][1:])),
            ).pop()
            array_index = self.table_obj.get_obj_list(
                int(re.sub("[^0-9]", "", instruction[3])),
            ).pop()

            variable_object = RegisterObject(
                reg, f"{array_obj.value}[{array_index.value}]",
            )
            self.table_obj.insert(index, variable_object)

        except IndexError as e:
            log.exception(f"{e} in AGET_KIND")

    def show_table(self):
        return self.table_obj.get_table()

    def _move_value_to_register(self, instruction, str_format, wide=False):
        destination = int(instruction[1][1:])
        source_list = [int(reg[1:]) for reg in instruction[2:]]
        self._transfer_register(source_list, destination, str_format)

        if wide:
            pair_source_list = [src + 1 for src in source_list]
            pair_destination = destination + 1
            self._transfer_register(
                pair_source_list, pair_destination, str_format
            )

    def _move_value_and_data_to_register(
        self, instruction, str_format, wide=False
    ):
        destination = int(instruction[1][1:])
        source_list = [int(reg[1:]) for reg in instruction[2:-1]]
        data = instruction[-1]

        self._transfer_register(
            source_list, destination, str_format, data=data
        )

        if wide:
            self._transfer_register(
                source_list, destination + 1, str_format, data=data
            )

    def _combine_value_to_register(self, instruction, str_format, wide=False):
        self._move_value_to_register(
            instruction[0:2] + instruction[1:], str_format, wide
        )

    def _transfer_register(
        self,
        source_list,
        destination,
        str_format,
        data=None,
    ):
        source_register_list = [
            self.table_obj.pop(index) for index in source_list
        ]

        value_dict = {
            f"src{index}": register.value
            for index, register in enumerate(source_register_list)
        }
        value_dict["data"] = data

        new_register = RegisterObject(
            f"v{destination}", str_format.format(**value_dict)
        )

        self.table_obj.insert(destination, new_register)


if __name__ == "__main__":
    pass
