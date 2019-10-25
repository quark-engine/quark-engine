from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex

a, d, dx = AnalyzeAPK("app-release.apk")

aa = []

print("搜尋函數:" + "sendTextMessage")
for method_set in dx.find_methods(".*", "sendTextMessage"):
    for _, call, _ in method_set.get_xref_from():
        aa.append((call.class_name, call.name))

print("第一層:\n")
for i in aa:
    print(i)
bb = []
for method_set in dx.find_methods(aa[0][0], aa[0][1]):
    for _, call, _ in method_set.get_xref_from():
        bb.append((call.class_name, call.name))


print("第二層:\n")

for i in bb:
    print(i)
