from quark.Objects.TableObject import TableObject
from quark.Objects.VarabileObject import VarabileObject

MAX_REG_COUNT = 40


class PyEval:
    def __init__(self):
        # Main switch for executing the bytecode instruction.
        self.eval = {
            "invoke-virtual": self.INVOKE_VIRTUAL,
            "invoke-direct": self.INVOKE_DIRECT,
            "invoke-static": self.INVOKE_STATIC,
            "move-result-object": self.MOVE_RESULT_OBJECT,
            "move-result": self.MOVE_RESULT,
            "new-instance": self.NEW_INSTANCE,
            "const-string": self.CONST_STRING,
            "const": self.CONST,
            "const/4": self.CONST_FOUR,
            "const/16": self.CONST_SIXTEEN,
            "const/high16": self.CONST_HIGHSIXTEEN,
            "const-wide": self.CONST_WIDE,
            "const-wide/16": self.CONST_WIDE_SIXTEEN,
            "const-wide/32": self.CONST_WIDE_THIRTY_TWO,
            "const-wide/high16": self.CONST_WIDE_HIGHSIXTEEN,
            "aget-object": self.AGET_OBJECT,
        }

        self.table_obj = TableObject(MAX_REG_COUNT)
        self.ret_stack = []

    def __invoke(self, instruction):
        """
        Function call in Android smali code.

        It will check if the corresponding table field
        has a value, if it does, inserts its own function
        name into called_by_func column.
        """

        executed_fuc = instruction[-1]
        reg_list = instruction[1: len(instruction) - 1]
        value_of_reg_list = []

        # query the value from hash table based on register index.
        for reg in reg_list:
            index = int(reg[1:])
            obj_stack = self.table_obj.get_obj_list(index)
            if len(obj_stack) > 0:
                var_obj = self.table_obj.pop(index)
                value_of_reg_list.append(var_obj.value)

        # insert the function and the parameter into called_by_func
        for reg in reg_list:
            index = int(reg[1:])
            obj_stack = self.table_obj.get_obj_list(index)
            if len(obj_stack) > 0:
                # add the function name into each parameter table
                var_obj = self.table_obj.pop(index)
                var_obj.called_by_func = f"{executed_fuc}({','.join(value_of_reg_list)})"

        # push the return value into ret_stack
        self.ret_stack.append(f"{executed_fuc}({','.join(value_of_reg_list)})")

    def INVOKE_VIRTUAL(self, instruction):
        """
        invoke-virtual { parameters }, methodtocall
        first parameter is "this".
        """
        # print("[Exec]:invoke-virtual")
        self.__invoke(instruction)

    def INVOKE_DIRECT(self, instruction):
        """
        invoke-direct { parameters }, methodtocall
        first parameter is "this".
        """
        # print("[Exec]:invoke-direct")
        self.__invoke(instruction)

    def INVOKE_STATIC(self, instruction):
        """
        invoke-static {parameters}, methodtocall
        """
        self.__invoke(instruction)

    def MOVE_RESULT_OBJECT(self, instruction):
        """
        move-result-object vx

        Save the value returned by the previous
        function call to the vx register,and then
        insert the VariableObject into table.
        """
        # print("[Exec]:move-result-object")

        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = VarabileObject(reg, pre_ret)
            self.table_obj.insert(index, variable_object)
        except Exception as e:
            # No element in pop
            pass

    def MOVE_RESULT(self, instruction):
        """
        move-result vx
        Move the result value of the previous method invocation into vx.

        Save the value returned by the previous
        function call to the vx register,and then
        insert the VariableObject into table.
        """
        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = VarabileObject(reg, pre_ret)
            self.table_obj.insert(index, variable_object)
        except Exception as e:
            # No element in pop
            pass

    def NEW_INSTANCE(self, instruction):
        """
        new-instance vx,type

        store variables to vx, and then
        insert the VariableObject into table.
        """
        # print("[Exec]: new-instance vx,type")

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST_STRING(self, instruction):
        """
        const-string vx,string_id

        store string variable to vx, and then
        insert the VariableObject into table.
        """
        # print("[Exec]: const-string vx,string_id")

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST(self, instruction):
        """
        const vx, lit32

        Puts the integer constant into vx
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST_FOUR(self, instruction):
        """
        const/4 vx,lit4

        store 4 bit constant into vx, and then
        insert the VariableObject into table.
        """
        # print("[Exec]: const/4 vx,lit4")

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST_SIXTEEN(self, instruction):
        """
        const/16 vx,lit16

        Puts the 4 bit constant into vx.
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST_HIGHSIXTEEN(self, instruction):
        """
        const/high16 v0, lit16
        Puts the 16 bit constant into the topmost bits of the register. Used to initialize float values.
        """

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = VarabileObject(reg, value)
        self.table_obj.insert(index, variable_object)

    def CONST_WIDE(self, instruction):
        """
        const-wide vx, lit64

        Puts the 64 bit constant into vx and vx+1 registers.
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])
        reg_plus_one = f"v{index + 1}"

        variable_object = VarabileObject(reg, value)
        variable_object2 = VarabileObject(reg_plus_one, value)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    def CONST_WIDE_SIXTEEN(self, instruction):
        """
        const-wide/16 vx, lit16

        Puts the integer constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])
        reg_plus_one = f"v{index + 1}"

        variable_object = VarabileObject(reg, value)
        variable_object2 = VarabileObject(reg_plus_one, value)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    def CONST_WIDE_THIRTY_TWO(self, instruction):
        """
        const-wide/32 vx, lit32

        Puts the 32 bit constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])
        reg_plus_one = f"v{index + 1}"

        variable_object = VarabileObject(reg, value)
        variable_object2 = VarabileObject(reg_plus_one, value)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    def CONST_WIDE_HIGHSIXTEEN(self, instruction):
        """
        const-wide/high16 vx,lit16

        Puts the 16 bit constant into the highest 16 bit of vx and vx+1 registers. Used to initialize double values.
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])
        reg_plus_one = f"v{index + 1}"

        variable_object = VarabileObject(reg, value)
        variable_object2 = VarabileObject(reg_plus_one, value)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    def AGET_OBJECT(self, instruction):
        """
        aget-object vx,vy,vz

        It means vx = vy[vz].
        """
        # print("[Exec]: aget-object vx,vy,vz")

        reg = instruction[1]
        index = int(reg[1:])

        try:

            array_obj = self.table_obj.get_obj_list(int(instruction[2][1])).pop()
            array_index = self.table_obj.get_obj_list(int(instruction[3][1])).pop()

            variable_object = VarabileObject(
                reg, f"{array_obj.value}[{array_index.value}]"
            )
            self.table_obj.insert(index, variable_object)
        except Exception as e:
            # No element in pop
            pass

    def show_table(self):
        return self.table_obj.get_table()


if __name__ == "__main__":
    pass
