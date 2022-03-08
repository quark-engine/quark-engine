# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

from multiprocessing.pool import Pool
from multiprocessing import cpu_count

from quark.core.analysis import QuarkAnalysis
from quark.core.quark import Quark

_quark = None


class ParallelQuark(Quark):
    @staticmethod
    def _worker_initializer(apk, core_library):
        global _quark
        _quark = Quark(apk, core_library)

    @staticmethod
    def _worker_analysis(rule_obj):
        _quark.quark_analysis = QuarkAnalysis()
        _quark.run(rule_obj)

        # Pack analysis result
        def to_raw_method(methodobject):
            return (
                methodobject.class_name,
                methodobject.name,
                methodobject.descriptor,
            )

        reached_stage = rule_obj.check_item.count(True)
        level_4_result = tuple(
            to_raw_method(method) for method in _quark.quark_analysis.level_4_result
        )
        behavior_list = [
            (
                to_raw_method(item["parent"]),
                to_raw_method(item["first_call"]),
                to_raw_method(item["second_call"]),
            )
            for item in _quark.quark_analysis.call_graph_analysis_list
        ]

        return (
            reached_stage,
            level_4_result,
            behavior_list,
            _quark.quark_analysis.parent_wrapper_mapping,
        )

    def _apply_analysis_result(self, rule_obj):
        async_result = self._result_map[id(rule_obj)]
        result = async_result.get()

        # Overwrite rule_obj
        for i in range(result[0]):
            rule_obj.check_item[i] = True

        # Overwrite quark analysis
        analysis = self.quark_analysis
        analysis.crime_description = rule_obj.crime

        apis = [
            self.apkinfo.find_method(
                rule_obj.api[i]["class"],
                rule_obj.api[i]["method"],
                rule_obj.api[i]["descriptor"],
            )
            for i in range(2)
        ]

        analysis.first_api, analysis.second_api = apis

        # analysis.level_1_result
        if result[0] >= 2:
            analysis.level_2_result = [api for api in apis if api]
        # analysis.level_3_result

        if result[0] >= 4:
            analysis.level_4_result = [
                self.apkinfo.find_method(method[0], method[1], method[2])
                for method in result[1]
            ]
            analysis.parent_wrapper_mapping = result[3]

        if result[0] >= 5:
            behavior_list = [
                tuple(
                    self.apkinfo.find_method(method[0], method[1], method[2])
                    for method in behavior
                )
                for behavior in result[2]
            ]

            analysis.level_5_result = [behavior[0]
                                       for behavior in behavior_list]

            analysis.call_graph_analysis_list.extend(
                [
                    {
                        "parent": behavior[0],
                        "first_call": behavior[1],
                        "second_call": behavior[2],
                        "apkinfo": self.apkinfo,
                        "first_api": analysis.first_api,
                        "second_api": analysis.second_api,
                        "crime": analysis.crime_description,
                    }
                    for behavior in behavior_list
                ]
            )

    def __init__(self, apk, core_library, num_of_process=1):
        self._result_map = {}
        self._pool = Pool(
            min(num_of_process, cpu_count() - 1), self._worker_initializer,
            (apk, core_library)
        )

        super().__init__(apk, core_library)

    def apply_rules(self, rule_obj_list):
        for rule_obj in rule_obj_list:
            result = self._pool.apply_async(self._worker_analysis, (rule_obj,))
            self._result_map[id(rule_obj)] = result

    def run(self, rule_obj):
        self._apply_analysis_result(rule_obj)

    def close(self):
        self._pool.close()
        self._pool.join()
