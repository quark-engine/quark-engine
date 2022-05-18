import pkg_resources


class ReportGenerator:
    """
    This module is for web report generating.
    """

    def __init__(self, json_report):

        self.json_report = json_report

        # Load html layout
        upper_html_path = pkg_resources.resource_filename(
            "quark.webreport", "upper.html"
        )
        lower_html_path = pkg_resources.resource_filename(
            "quark.webreport", "lower.html"
        )
        with open(upper_html_path) as file:
            self.upperHTML = file.read()
            file.close()

        with open(lower_html_path) as file:
            self.lowerHTML = file.read()
            file.close()

    def generate(self):
        """
        Load the quark JSON report and generate the HTML of the Quark web report.

        :return: the string of Quark web report HTML
        """

        analysis_result = self.json_report["crimes"]
        filesize = format(
            float(self.json_report["size_bytes"])/float(1024*1024), '.2f',
        )
        filename = self.json_report["apk_filename"]
        md5 = self.json_report["md5"]

        rule_number_set = {
            "all": len(analysis_result),
            "100%": _count_confidence_rule_number(analysis_result, "100%"),
            "80%": _count_confidence_rule_number(analysis_result, "80%"),
            "60%": _count_confidence_rule_number(analysis_result, "60%"),
            "40%": _count_confidence_rule_number(analysis_result, "40%"),
            "20%": _count_confidence_rule_number(analysis_result, "20%"),
            "0%": _count_confidence_rule_number(analysis_result, "0%"),
        }

        # Get all labels
        five_stages_labels = _get_five_stages_labels(analysis_result)
        all_labels = _get_all_labels(analysis_result)

        report_data_html = _insert_json_report(analysis_result)
        radarechar_html = _generate_radarechart_html(
            five_stages_labels, all_labels,
        )
        sample_info_html = _generate_sample_info_html(
            rule_number_set, filename, md5, filesize, five_stages_labels,
        )
        analysis_result_html = _generate_report_html(analysis_result)

        report_html = self.upperHTML + \
            sample_info_html + \
            radarechar_html + \
            analysis_result_html + \
            report_data_html + \
            self.lowerHTML

        return report_html


def _insert_json_report(data):
    """
    Convert the quark JSON report to HTML with script tag.

    :param data: the dict of Quark JSON report
    :return: the string of Quark JSON report HTML
    """

    return f"""<script>var reportData = {str(data)}</script>"""


def _get_five_stages_labels(data):
    """
    Get the labels with 100% confidence crimes.

    :param data: the dict of Quark JSON report
    :return: the set contain all lebels with 100% confidence crimes
    """

    five_stage_label_set = set()
    for item in data:
        if item["confidence"] == "100%":
            five_stage_label_set.update(item["label"])

    return five_stage_label_set


def _get_all_labels(data):
    """
    Get all labels with crimes above 0% confidence.

    :param data: the dict of Quark JSON report
    :return: the set contain all labels with crimes above 0% confidence
    """

    all_label_set = set()
    for item in data:
        if not item["confidence"] == "0%":
            all_label_set.update(item["label"])

    return all_label_set


def _count_confidence_rule_number(data, confidence):
    """
    Get the number of rules with given confidence in JSON report.

    :param data: the dict of Quark JSON report
    :param confidence: the string of given confidence
    :return: the int for the number of rules with given confidence in JSON report
    """

    count = 0
    for item in data:
        if item["confidence"] == confidence:
            count += 1
    return count


def _generate_radarechart_html(five_stages_labels, all_labels):
    """
    Generate the HTML of radare chart secton in Quark web report.

    :param five_stages_labels: the set of lebels with 100% confidence crimes
    :param all_labels: the set contain all labels with crimes above 0% confidence
    :return: the string of HTML radare chart secton
    """

    five_labels_html = ""
    for label in five_stages_labels:
        five_labels_html += f"""<label class="label-tag">{label}</label>"""

    all_labels_html = ""
    for label in all_labels:
        all_labels_html += f"""
            <label id="collection" class="label-container">{label}
                <input class="rule-label" type="checkbox" name="label" value="{label}">
                <span class="checkmark"></span>
            </label>
        """

    radarchart_html = f"""
        <div class="row radar-chart">
            <div class="col-md-6"><canvas id="myChart" width="400" height="400"></canvas></div>
            <div class="col-md-6">
                <h3>Select lables to see max confidence in radare chart</h3>
                <div class="label-group">
                    {all_labels_html}
                </div>
                <button class="deselect" onclick="deselect()">Deselect all</button>
                <h3>The labels with 100% confidence crimes</h3>
                <div class="label-group">
                    {five_labels_html}
                </div>
            </div>
        </div>
        <div class="row filter-bar">
            <div class="col-md-9">
                <label>Search crime</label>
                <input type="text" id="search" onkeyup="search()" placeholder="Search for crime description..">
            </div>
            <div class="col-md-3">
                <label>Confidence filter</label>
                <div class="box">
                    <select onchange="confidenceFilter(value);">
                    <option value="" selected disabled hidden>Select confidence.. </option>
                    <option>100%</option>
                    <option>80%</option>
                    <option>60%</option>
                    <option>40%</option>
                    <option>20%</option>
                    <option>0%</option>
                    </select>
                </div>
            </div>
        </div>
        <div class="row report-crimes">
            <div class="table-wrap border">
                <table id="report" class="table align-middle mb-0 bg-white">
                    <thead class="bg-light">
                        <tr>
                        <th>Rule No.</th>
                        <th>Crime Description</th>
                        <th>Confidence</th>
                        </tr>
                    </thead>
                    <tbody>


    """
    return radarchart_html


def _generate_report_html(data):
    """
    Generate the HTML of summary report secton in Quark web report.

    :param data: the dict of Quark JSON report
    :return: the string of HTML summary report secton
    """

    confidence_badge = {
        "0%": "badge-secondary",
        "20%": "badge-success",
        "40%": "badge-info",
        "60%": "badge-primary",
        "80%": "badge-warning",
        "100%": "badge-danger",
    }

    contentHTML = ""
    for crime in data:
        description = crime["crime"]
        confidence = crime["confidence"]
        rule_number = crime["rule"].split('.')[0]
        contentHTML += f"""
            <tr>
                <td><p class="fw-normal mb-1">{rule_number}</p></td>
                <td><p class="fw-normal mb-1">{description}</p></td>
                <td><span class="badge {confidence_badge[confidence]}">{confidence}</span></td>
            </tr>
        """
    return contentHTML


def _generate_sample_info_html(rules_number_set, filename, md5, filesize, labels):
    """
    Generate the HTML of sample information secton in Quark web report.

    :param rules_number_set: the dict of the rule number for each confidence
    :param filename: the string of the sample filename
    :param md5: the string of the sample md5 hash value
    :param filesize: the string of the sample filesize
    :param labels: the set of lebels with 100% confidence crimes
    :return: the string of HTML sample infromation secton
    """

    five_labels_html = ""
    for label in labels:
        five_labels_html += f"""<label class="label-tag">{label}</label>"""

    return f"""
    <div class="container">
        <div class="row justify-content-center"><div class="col-md-6 text-center mb-5"><img class="logo" src="https://quark-engine.github.io/ruleviewer/quark-logo.png"/></div></div>
        <div class="row">
            <div class="col-sm-7 report-sample-info" style="max-width: 100%;flex: 0 0 48%;">
                <div class="row">
                    <div class="col-sm-6"><div role="progressbar" aria-valuenow="{rules_number_set["100%"]}" aria-valuemin="0" aria-valuemax="{rules_number_set["all"]}" style="--value:{rules_number_set["100%"]}"></div></div>
                    <div class="col-sm-6">
                        <h4>Analysis Result</h4>
                        <p style="font-size: 1.25rem;">The # of rules for each confidence</p>
                        <div class="row" style="margin-left: auto;margin-top: 20px;">
                            <div class="col-sm-6 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-danger badge-result">100%</span>  {rules_number_set["100%"]}</div></div>
                            <div class="col-sm-5 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-warning badge-result">80%</span>  {rules_number_set["80%"]}</div></div>
                            <div class="col-sm-6 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-primary badge-result">60%</span>  {rules_number_set["60%"]}</div></div>
                            <div class="col-sm-5 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-info badge-result">40%</span>  {rules_number_set["40%"]}</div></div>
                            <div class="col-sm-6 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-success badge-result">20%</span>  {rules_number_set["20%"]}</div></div>
                            <div class="col-sm-5 sample-info-lable"><div class="confidence"><span class="confidence-tag badge-secondary badge-result">0%</span>  {rules_number_set["0%"]}</div></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-sm-6 report-sample-info" style="margin-left:30px; font-size: 140%; margin-right: -300px;">
                <div class="row">
                    <div class="col-sm-12">
                        <h4>Sample Information</h4>
                        <div class="row" style="margin-left: auto;margin-top: 20px;">
                            <dt class="col-sm-3 sample-info-lable">File name</dt>
                            <dd class="col-sm-9 sample-info-lable">{filename}</dd>
                            <dt class="col-sm-3 sample-info-lable">MD5</dt>
                            <dd class="col-sm-9 sample-info-lable">{md5}</dd>
                            <dt class="col-sm-3 sample-info-lable">File size</dt>
                            <dd class="col-sm-9 sample-info-lable">{filesize} Mb</dd>
                            <dt class="col-sm-3 sample-info-lable">Labels</dt>
                            <dd class="col-sm-9 sample-info-lable">
                                <div class="label-s">
                                {five_labels_html}
                                </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    """
