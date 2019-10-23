from RuleObject import RuleObject
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex

# TODO  whenever use the list(), need to check it is NoneType or not


class x_rule:
    def __init__(self, apk):
        self.a, self.d, self.dx = AnalyzeAPK(apk)

        # Create Class, Method, String and Field crossreferences
        # for all classes in the Analysis.
        self.dx.create_xref()

    @property
    def permissions(self):

        return self.a.get_permissions()

    def methods(self, class_name=".*", method_name=".*"):

        result = self.dx.find_methods(class_name, method_name)

        if (result is not None) and len(list(result)) > 0:
            return self.dx.find_methods(class_name, method_name)

        else:
            return None

    def upperFunc(self, class_name, method_name):
        result = []
        method_set = self.methods(class_name, method_name)

        if method_set is not None:
            for md in method_set:
                for _, call, _ in md.get_xref_from():
                    result.append(call.name)

            return self._remove_dup(result)
        else:
            return None

    def _remove_dup(self, element):
        return list(set(element))

    def find_intersection(self, list1, list2, depth=1):

        # Limit up to three layers of the recursions.
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


rule_checker = RuleObject("sendLocation.json")


# Level 1
if set(rule_checker.x1_permission).issubset(set(data.permissions)):
    print("[O]有使用權限: \n" + ",".join(rule_checker.x1_permission))

# Level 2
test_md0 = rule_checker.x2n3n4_comb[0]["method"]
test_cls0 = rule_checker.x2n3n4_comb[0]["class"]
if data.methods(test_cls0, test_md0) is not None:
    print("[O]有使用method: \n" + test_md0)

    test_md1 = rule_checker.x2n3n4_comb[1]["method"]
    test_cls1 = rule_checker.x2n3n4_comb[1]["class"]

    # Level 3
    if data.methods(test_cls1, test_md1) is not None:
        print("[O]也有使用method: \n" + test_md1)

    # Level 4
    upperfunc0 = data.upperFunc(test_cls0, test_md0)
    upperfunc1 = data.upperFunc(test_cls1, test_md1)

    same = data.find_intersection(upperfunc0, upperfunc1)
    if same is not None:
        print("[O]共同出現於:\n" + repr(same))
