import re
import json
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex


class x_rule:
    def __init__(self, apk):
        self.a, self.d, self.dx = AnalyzeAPK(apk)

    @property
    def permissions(self):
        return self.a.get_permissions()

    def methods(self, class_name=".*", method_name=".*"):

        self.dx.create_xref()

        return self.dx.find_methods(classname=class_name, methodname=method_name)


data = x_rule("14d9f1a92dd984d6040cc41ed06e273e.apk")

with open("sendSMS.json", "r") as f:
    jl = json.loads(f.read())

    if jl["x1_permission"] in data.permissions:
        print("有權限:" + jl["x1_permission"])

    if len(list(data.methods(method_name=jl["x2_method"]))) > 0:
        print("有Method:" + jl["x2_method"])

    if len(
        list(data.methods("Landroid/telephony/SmsManager", jl["x3_combination"][0]))
    ):
        print("有Method:" + jl["x3_combination"][0])
