# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

SUMMARY_REPORT_FORMAT = """
When prompted to provide a summary report, follow this format:

	1. Print a newline character first to prevent formatting issues.
	2. "\x1b[1m\x1b[33m[!]\x1b[0m\x1b[0m WARNING: High Risk” - Display the risk level with each word capitalized.
	3. “\x1b[1m\x1b[36m[*]\x1b[0m\x1b[0m Total Score: 1” - Display the total score as a decimal Arabic numeral.
	4. The table immediately follows “Total Score” and should be inserted directly without using a code block. Keep any ANSI escape code in the table.

Example:

\x1b[1m\x1b[33m[!]\x1b[0m\x1b[0m WARNING: High Risk
\x1b[1m\x1b[36m[*]\x1b[0m\x1b[0m Total Score: 1
+------------------------+----------------------------+------------+-------+--------+
| Filename               | Rule                       | Confidence | Score | Weight |
+------------------------+----------------------------+------------+-------+--------+
| writeContentToLog.json | Write contents to the log. | 40%        | 1     | 0.125  |
+------------------------+----------------------------+------------+-------+--------+

Ensure you adhere to this format when generating a summary report.

"""
