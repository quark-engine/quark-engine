import os
import json

from tqdm import tqdm
from quark.core.struct.ruleobject import RuleObject
from quark.webreport.generate import ReportGenerator


class RuleGeneration:
    """
    This module is for generating rules with the APIs in a specific method.
    """

    def __init__(self, quark, output_dir):
        self.quark = quark
        self.apkinfo = self.quark.apkinfo
        self.output_dir = output_dir
        self.first_api_set = set()
        self.second_api_set = set()

        # Parse smali code into classname methodname and descriptor.

        self.first_api_set, self.second_api_set = self.api_filter()

        return

    def api_filter(self, percentile_rank=0.2):
        """
        Sorting APIs by the number of APIs used in APK,
        and split APIs into P_set (less used number)
        and S_set (more used number)
        by percentile_rank (default 20%).

        :param percentile_rank: The int for rank of percentile.
        :return P_set: a set of APIs that less used.
        :return S_set: a set of APIs that more used.
        """
        statistic_result = {}
        str_statistic_result = {}
        api_pool = self.apkinfo.android_apis

        for api in api_pool:
            api_called_count = len(self.apkinfo.upperfunc(api))
            if api_called_count > 0:
                statistic_result[str(api)] = api_called_count
                str_statistic_result[str(api)] = api

        sorted_key = {k: v for k, v in sorted(
            statistic_result.items(), key=lambda item: item[1])}
        sorted_result = {k: v for k, v in sorted(sorted_key.items())}

        threshold = len(api_pool) * percentile_rank
        P_set = []
        S_set = []

        for i, (api, _) in enumerate(sorted_result.items()):
            if i < threshold:
                P_set.append(str_statistic_result[api])
                continue
            S_set.append(str_statistic_result[api])

        return P_set, S_set

    def generate_rule(self, web_report=None, stage=1):
        """
        Generate rules and export them to the output directory.

        :return: None
        """

        if stage == 1:
            first_apis_pool = list(self.first_api_set)
            second_apis_pool = list(self.second_api_set)
        elif stage == 2:
            first_apis_pool = list(self.first_api_set)
            second_apis_pool = list(self.second_api_set)
        elif stage == 3:
            first_apis_pool = list(self.first_api_set)
            second_apis_pool = list(self.second_api_set)
        elif stage == 4:
            first_apis_pool = list(self.first_api_set)
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

                if not comb.check_item[4]:
                    continue

                if web_report:
                    generated_rule["number"] = rule_number
                    self.generated_result.append(generated_rule)
                    rule_number += 1

                else:
                    rule_name = f"{rule_number}.json"
                    rule_path = os.path.join(self.output_dir, rule_name)
                    with open(rule_path, "w") as rule_file:
                        json.dump(generated_rule, rule_file, indent=4)

                    rule_number += 1

        if web_report:
            web_report_data = {
                "apk_filename": self.quark.apkinfo.filename,
                "md5": self.quark.apkinfo.md5,
                "size_bytes": self.quark.apkinfo.filesize,
                "result": self.generated_result
            }

            report_html = ReportGenerator(
                web_report_data).get_rule_generate_report_html()

            if ".html" not in web_report:
                web_report = f"{web_report}.html"

            with open(web_report, "w") as file:
                file.write(report_html)
                file.close()

        # Clear progress bar
        outter_loop.clear()
        outter_loop.close()
        return
