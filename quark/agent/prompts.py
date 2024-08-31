# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

SUMMARY_REPORT_FORMAT = """
When prompted to provide a summary report, follow these rules and the summary report example:

	1. Print a newline character first to prevent formatting issues.
	2. Change "<RISK_LEVEL>" in "WARNING: <RISK_LEVEL>" to the risk level with the first letter of each word capitalized.
	3. Change "<TOTAL_SCORE>" in "Total Score: <TOTAL_SCORE>" to the total score, expressed as a decimal numeral.
	4. Without using a code block, place the output of the tool, getSummaryReportTable, in the line directly after "Total Score: <TOTAL_SCORE>".

The Summary Report Example:

[!] WARNING: <RISK_LEVEL>
[*] Total Score: <TOTAL_SCORE>
+--------------------------------+-----------------------------+------------+-------+--------+  
| Filename                       | Rule                        | Confidence | Score | Weight |  
+--------------------------------+-----------------------------+------------+-------+--------+  
| constructCryptoGraphicKey.json | Construct cryptographic key | 100%       | 1     | 1.0    |  
+--------------------------------+-----------------------------+------------+-------+--------+ 

Ensure you adhere to these rules and the example when providing a summary report.

"""

PREPROMPT = """
Before beginning the analysis of samples,
please disregard any previously remembered detection processes.
Unless specifically requested by the user,
do not assume any detection procedures.
"""
