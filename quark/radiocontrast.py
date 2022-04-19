# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
import json

from tqdm import tqdm
from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject


class RadioContrast:
    """
    This module is for generating rules with the APIs in a specific method.
    """

    def __init__(self, apk_path, target_method, output_dir, max_search_layer=3):
        self.quark = Quark(apk_path)
        self.apkinfo = self.quark.apkinfo

        # Parse smali code into classname methodname and descriptor.
        classname = target_method.split("->")[0]
        methodname = target_method.split("->")[1].split("(")[0]
        descriptor = "(" + target_method.split("->")[1].split("(")[1]

        self.method = self.apkinfo.find_method(
            class_name=classname, method_name=methodname, descriptor=descriptor,
        )

        if self.method is None:
            raise ValueError("Target method not found!")

        self.output_dir = output_dir
        self.api_set = set()
        self.max_search_layer = max_search_layer
        return

    def method_recursive_search(self, method_set, depth=1):
        """
        Find all APIs in the target method.

        :param method_set: the list that contains each MethodAnalysis.
        :param depth: maximum number of recursive search functions.
        :return: a set of first_method_list ∩ second_method_list or None.
        """

        # Not found same method usage, try to find the next layer.
        depth += 1
        if depth > self.max_search_layer:
            return

        # Append first layer into next layer.
        next_level_set = method_set.copy()

        # Extend the xref from function into next layer.
        for md in next_level_set:
            if md[0].is_android_api():
                self.api_set.add(md[0])
                continue

            self.method_recursive_search(self.apkinfo.lowerfunc(md[0]), depth)

    def rule_generate(self):
        """
        Generate rules and export them to the output directory.

        :return: None
        """
        # Rescursive search for apis in target method.
        lower_funcs = set(self.apkinfo.lowerfunc(self.method))
        self.method_recursive_search(lower_funcs)

        first_apis_pool = list(self.api_set)
        second_apis_pool = list(self.api_set)

        # Setup progress bar.
        second_api_pool_num = len(second_apis_pool)
        outter_loop = tqdm(first_apis_pool)

        # The number of rule file.
        rule_number = 1

        for api1 in first_apis_pool:
            outter_loop.update(1)

            for num, api2 in enumerate(second_apis_pool, start=1):
                inner_desc = f"{num}/{second_api_pool_num}"
                outter_loop.set_postfix(inner_loop=inner_desc, refresh=True)

                # Skip the case of same method.
                if api2.name == api1.name:
                    continue

                generated_rule = {
                    "crime": "",
                    "permission": [],
                    "api": [
                        {
                            "class": api1.class_name,
                            "method": api1.name,
                            "descriptor": api1.descriptor,
                        },
                        {
                            "class": api2.class_name,
                            "method": api2.name,
                            "descriptor": api2.descriptor,
                        },
                    ],
                    "score": 1,
                    "label": [],
                }
                comb = RuleObject("test", json_data=generated_rule)

                try:
                    self.quark.run(comb)
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    tqdm.write(
                        "{} and {} combination has some error when analyzing,\
                        ERROR MESSAGE: {}".format(
                            api1, api2, e,
                        ),
                    )
                    continue

                if comb.check_item[4]:
                    rule_name = f"{rule_number}.json"
                    rule_path = os.path.join(self.output_dir, rule_name)
                    with open(rule_path, "w") as rule_file:
                        json.dump(generated_rule, rule_file, indent=4)

                    rule_number += 1

        # Clear progress bar
        outter_loop.clear()
        outter_loop.close()
        return


if __name__ == "__main__":
    pass
