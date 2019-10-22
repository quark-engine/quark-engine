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

        self.dx.create_xref()

        result = self.dx.find_methods(class_name, method_name)

        if len(list(result)) > 0:
            return self.dx.find_methods(class_name, method_name)

        else:
            return None

    def upperFunc(self, class_name, method_name):
        result = None
        method_set = self.methods(class_name, method_name)
        xref = list(method_set)[0]

        for _, call, _ in xref.get_xref_from():
            result = call.name
        return result


data = x_rule("14d9f1a92dd984d6040cc41ed06e273e.apk")

with open("sendLocation.json", "r") as f:
    jl = json.loads(f.read())

    if set(jl["x1_permission"]).issubset(set(data.permissions)):
        print("[O]有使用權限:" + ",".join(jl["x1_permission"]))

    test_md0 = jl["x2n3n4_comb"][0]["method"]
    test_cls0 = jl["x2n3n4_comb"][0]["class"]
    if data.methods(test_cls0, test_md0) is not None:
        print("[O]有使用method: " + test_md0)

    upperfunc0 = data.upperFunc(test_cls0, test_md0)

    test_md1 = jl["x2n3n4_comb"][1]["method"]
    test_cls1 = jl["x2n3n4_comb"][1]["class"]

    upperfunc1 = data.upperFunc(test_cls1, test_md1)

    if data.methods(test_cls1, test_md1) is not None:
        print("[O]有使用method: " + test_md1)

    print(upperfunc0, upperfunc1)

