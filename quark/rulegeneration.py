import os
import json

from tqdm import tqdm
from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from quark.webreport.generate import ReportGenerator
from quark.utils.tools import filter_api_by_usage_count


class RuleGeneration:
    """
    This module is for generating rules with the APIs
    that are 20% least usage count in the given APK
    """

    def __init__(self, apk, output_dir):
        self.quark = Quark(apk)
        self.apkinfo = self.quark.apkinfo
        self.api_set = self.apkinfo.android_apis
        self.output_dir = output_dir
        self.first_api_set, self.second_api_set = filter_api_by_usage_count(
            self.apkinfo, self.api_set, percentile_rank=0.2)

        return

    def generate_rule(self, web_editor=None, stage=1):
        """
        Generate rules and export them to the output directory.

        :param web_editor: The path of the web editor.
        :param stage: The int for stage of rule generation.
        :return: None
        """

        if stage == 1:
            first_apis_pool = list(self.first_api_set)
            second_apis_pool = list(self.first_api_set)
        elif stage == 2:
            first_apis_pool = list(self.first_api_set)
            second_apis_pool = list(self.second_api_set)
        elif stage == 3:
            first_apis_pool = list(self.second_api_set)
            second_apis_pool = list(self.first_api_set)
        elif stage == 4:
            first_apis_pool = list(self.second_api_set)
            second_apis_pool = list(self.second_api_set)
        elif stage == 0:
            first_apis_pool = list(self.first_api_set) + \
                list(self.second_api_set)
            second_apis_pool = list(self.first_api_set) + \
                list(self.second_api_set)

        self.generated_result = list()

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
                comb = RuleObject("test", jsonData=generated_rule)

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

                if not comb.check_item[4]:
                    continue

                if web_editor:
                    generated_rule["number"] = rule_number
                    self.generated_result.append(generated_rule)
                    rule_number += 1

                else:
                    rule_name = f"{rule_number}.json"
                    rule_path = os.path.join(self.output_dir, rule_name)
                    with open(rule_path, "w") as rule_file:
                        json.dump(generated_rule, rule_file, indent=4)

                    rule_number += 1

        if web_editor:
            web_editor_data = {
                "apk_filename": self.quark.apkinfo.filename,
                "md5": self.quark.apkinfo.md5,
                "size_bytes": self.quark.apkinfo.filesize,
                "result": self.generated_result
            }

            editor_html = ReportGenerator(
                web_editor_data).get_rule_generate_editor_html()

            if ".html" not in web_editor:
                web_editor = f"{web_editor}.html"

            with open(web_editor, "w") as file:
                file.write(editor_html)
                file.close()

        # Clear progress bar
        outter_loop.clear()
        outter_loop.close()
        return
