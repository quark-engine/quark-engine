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

        result = self.dx.find_methods(classname=class_name, methodname=method_name)

        if len(list(result)) > 0:
            return self.dx.find_methods(classname=class_name, methodname=method_name)

        else:
            return None

    def upperFunc(self, class_name, method_name):
        result = []
        method_set = self.methods(class_name, method_name)
        xref = list(method_set)[0]

        for _, call, _ in xref.get_xref_from():
            result.append(call.name)
        return result


data = x_rule("14d9f1a92dd984d6040cc41ed06e273e.apk")

with open("sendSMS.json", "r") as f:
    jl = json.loads(f.read())

    if jl["x1_permission"] in data.permissions:
        print("[O]有使用權限:" + jl["x1_permission"])

    if data.methods(method_name=jl["x2_method"]) is not None:
        print("[O]有使用權限:" + jl["x2_method"])

    up1 = data.upperFunc(".*", jl["x2_method"])
    up2 = data.upperFunc("Landroid/telephony/SmsManager", jl["x3_combination"][0])

    if up1 == up2:
        print("[O]有組合出現:" + jl["x2_method"] + " " + jl["x3_combination"][0])
