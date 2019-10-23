import re
import json
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex

# TODO  whenever use the list(), need to check it is NoneType or not


class x_rule:
    def __init__(self, apk):
        self.a, self.d, self.dx = AnalyzeAPK(apk)

    @property
    def permissions(self):
        return self.a.get_permissions()

    def methods(self, class_name=".*", method_name=".*"):

        # self.dx.create_xref()

        result = self.dx.find_methods(class_name, method_name)

        if len(list(result)) > 0:
            return self.dx.find_methods(class_name, method_name)

        else:
            return None

    def upperFunc(self, class_name, method_name):
        result = []
        method_set = self.methods(class_name, method_name)

        for md in method_set:
            for _, call, _ in md.get_xref_from():
                result.append(call.name)

        return self._remove_dup(result)

    def _remove_dup(self, element):
        return list(set(element))

    def find_intersection(self, list1, list2, depth=1):
        # TODO tail call optimization

        # Limit up to three layers of recursions
        if depth == 3:
            return None

        result = set(list1).intersection(list2)
        if len(result) > 0:
            return result
        else:
            # Not found same method usage, try to find next layer.

            sec_list1 = []
            sec_list2 = []
            for item in list1:
                sec_list1 = self.upperFunc(".*", item)
            for item in list2:
                sec_list2 = self.upperFunc(".*", item)
            # Append first layer into next layer
            for pre_list in list1:
                sec_list1.append(pre_list)
            for pre_list in list2:
                sec_list2.append(pre_list)

            depth += 1

            return self.find_intersection(sec_list1, sec_list2, depth)


data = x_rule("14d9f1a92dd984d6040cc41ed06e273e.apk")

with open("sendLocation.json", "r") as f:
    jl = json.loads(f.read())

    if set(jl["x1_permission"]).issubset(set(data.permissions)):
        print("[O]有使用權限:" + ",".join(jl["x1_permission"]))

    test_md0 = jl["x2n3n4_comb"][0]["method"]
    test_cls0 = jl["x2n3n4_comb"][0]["class"]
    if data.methods(test_cls0, test_md0) is not None:
        print("[O]有使用method: " + test_md0)

    test_md1 = jl["x2n3n4_comb"][1]["method"]
    test_cls1 = jl["x2n3n4_comb"][1]["class"]

    if data.methods(test_cls1, test_md1) is not None:
        print("[O]有使用method: " + test_md1)

    upperfunc0 = data.upperFunc(test_cls0, test_md0)
    upperfunc1 = data.upperFunc(test_cls1, test_md1)

    same = data.find_intersection(upperfunc0, upperfunc1)
    if same is not None:
        print("[O]共同出現於:" + repr(same))
