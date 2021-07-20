import hashlib
import os
import time

import requests
from tqdm import tqdm

from quark.utils.colors import green, red, yellow


class VTAnalysis:
    def __init__(self, api_keys_list, waiting_time=16):

        self.REPORT_URL = "https://www.virustotal.com/vtapi/v2/file/report"
        self.SCAN_URL = "https://www.virustotal.com/vtapi/v2/file/scan"

        self.api_keys_list = {}
        for api_key in api_keys_list:
            self.api_keys_list[api_key] = True

        self.api_key = api_keys_list[0]

        self.reports = {}

        # A queue for uploaded file but waiting for retrieve report
        self.waiting_queue = set()

        self.WAITING_TIME = waiting_time

    def get_api_keys_list(self):
        return self.api_keys_list

    def get_file_md5(self, file):
        md5 = hashlib.md5()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest()

    def set_progress(self, progress):
        self.reports.update(progress)

    def change_api_key(self):
        tqdm.write(f"[*] {self.api_key} is unavailable, change another API key")
        self.api_keys_list[self.api_key] = False
        for api_key in self.api_keys_list:
            if self.api_keys_list[api_key]:
                self.api_key = api_key
                return True

        tqdm.write(red(f"[ERROR] There is no available api key"))
        return False

    def check_api_key_available(self):
        tqdm.write("[*] Check API keys available")

        for api_key in self.api_keys_list:
            try:
                params = {
                    "apikey": api_key,
                    "resource": "34efc3ebf51a6511c0d12cce7592db73",
                }
                res = requests.get(self.REPORT_URL, params)

                tqdm.write(f"API {api_key}: {res.status_code}")
                if res.status_code == 200:
                    self.api_keys_list[api_key] = True
                elif res.status_code == 403:
                    self.api_keys_list[api_key] = False
                elif res.status_code == 204:
                    self.api_keys_list[api_key] = False
                elif res.status_code == 400:
                    tqdm.write("Failed to check api key: Bad Request.")
            except Exception as e:
                tqdm.write(red(f"[ERROR] Failed to check api: {api_key}"))
                continue

    def get_reports(self, all_info=False):

        if all_info:
            return self.reports

        positives_report = {}
        for file_md5 in self.reports:
            if self.reports[file_md5] > 0:
                positives_report[file_md5] = self.reports[file_md5]

        return positives_report

    def retreive_report(self, file_md5):
        params = {"apikey": self.api_key, "resource": file_md5}
        res = requests.get(self.REPORT_URL, params)

        if res.status_code == 200:
            return res.json()
        else:
            if not self.change_api_key():
                return False
            return self.retreive_report(file_md5)

    def scan_file(self, filename, file):
        params = {
            "apikey": self.api_key,
        }

        files = {"file": (filename, file)}

        res = requests.post(self.SCAN_URL, files=files, params=params)

        if res.status_code == 200:
            return res.json()
        else:
            if not self.change_api_key():
                return False
            return self.scan_file(filename, file)

    def analyze_single_file(self, path):

        if not os.path.isfile(path):
            tqdm.write(red(f"[*] Error: Given path is not a file: {path}"))
            return

        # Retreive file report
        tqdm.write(f"[*] Retrieved file scan report: {path}")
        file_md5 = self.get_file_md5(path)

        if file_md5 in self.reports:
            tqdm.write(green(f"[*] {file_md5} already retrieved report"))
            return self.reports[file_md5]

        report = self.retreive_report(file_md5)
        time.sleep(self.WAITING_TIME)

        if not report:
            tqdm.write(red(f"[*] ERROR: All API keys are unavailable"))
            return -1

        if report["response_code"] == 1:
            self.reports[file_md5] = report["positives"]
            return report["positives"]

        # Upload file to VT
        tqdm.write(f"[*] Upload file: {path}")
        with open(path, "rb") as f:
            scan_result = self.scan_file(os.path.basename(path), f)
        time.sleep(self.WAITING_TIME)

        if not scan_result:
            tqdm.write(red(f"[*] ERROR: All API keys are unavailable"))
            return -1

        if scan_result["response_code"] == 0:
            tqdm.write(red(f"[*] ERROR: Failed to upload file: {path}"))
            return

        tqdm.write(f"[*] Retrieve file scan reports again")

        re_report = self.retreive_report(file_md5)
        time.sleep(self.WAITING_TIME)

        if not re_report:
            tqdm.write(red(f"[*] ERROR: All API keys are unavailable"))
            return -1

        if re_report["response_code"] == 1:
            self.reports[file_md5] = report["positives"]
            return report["positives"]
        else:
            tqdm.write(f"[*] Unable to retrieve {file_md5}, add to waiting queue")
            self.waiting_queue.add(file_md5)
            return

    def analyze_multi_file(self, path):

        if not os.path.isdir(path):
            tqdm.write(red(f"[*] Error: Given path is not a directory: {path}"))
            return

        file_count = sum(len(files) for _, _, files in os.walk(path))

        progress_bar = tqdm(total=file_count)
        for root, dirs, files in os.walk(path):  # Walk the directory
            for name in files:

                file_path = os.path.join(root, name)

                try:
                    result = self.analyze_single_file(file_path)
                    progress_bar.update(1)  # Increment the progress bar

                    # All API keys are unavailable
                    if result == -1:
                        return

                    if not result:
                        continue

                    # Found positives file
                    if result > 0:
                        tqdm.write(green(f"[*] Found positives file: {file_path}"))

                except Exception as e:
                    tqdm.write(yellow(f"[WARN] Exception found: {e.message}"))
                    continue

        progress_bar.close()

        # Retrieve the file report from waiting queue
        tqdm.write(f"[*] Start to retrieve file report from waiting queue")
        for file_md5 in tqdm(self.waiting_queue):

            try:
                report = self.retreive_report(file_md5)

                if not report:
                    tqdm.write(red(f"[*] ERROR: All API keys are unavailable"))
                    return -1

                if report["response_code"] == 1:
                    self.reports[file_md5] = report["positives"]

            except Exception as e:
                tqdm.write(yellow(f"[WARN] Exception found: {e.message}"))
                continue


if __name__ == "__main__":
    pass
