++++++++++++++++++++++++++++++++++++++++
Report
++++++++++++++++++++++++++++++++++++++++


Web Report
------------------------
You can analyze an APK sample and produce a beautiful summary report in HTML format through the following command.

::

    quark -a Ahmyth.apk -s -w test.html 

The meanings of the options:

* -a, APK sample file input
* -s, Show summary report
* -w, Generate Web Report output

Here is a `demo <https://pulorsok.github.io/ruleviewer/web-report-demo>`_ of the Web Report. The image below demonstrates the overview of the Web Report. 

.. figure:: https://camo.githubusercontent.com/9e25807aa6c0173b995dd94f867c7eae461e29a61537d1791c3633d33e913041/68747470733a2f2f692e696d6775722e636f6d2f684733416738742e706e67
   :width: 90%


Analysis Result
==========================
First, at the top-left corner, there is an Analysis Result section. It gives you the statistics of the crimes detected by Quark.

It contains two parts in this section:

Doughnut Chart
  A doughnut chart shows the ratio of the crimes with 100% confidence in all crimes detected. 

Statistics
  Statistics show crimes in different confidence levels from 0% to 100%. The higher the level is, the more we are sure the behavior is malicious.

    
Sample Information
==========================
At the top-right corner, Sample Information shows the basic information of the sample, including the file name, MD5 hash value, file size, and the labels of detected rules with 100% confidence. 



Radar Chart
==========================
In this section, you can generate a custom radar chart using labels from detected rules. 
This way, you can compare the confidence level of different dimensions in the sample in an easy-to-understand form. 

1. First, you can choose the labels you want as the dimensions to analyze in the label section on the right.

2. Then, the page will plot the radar chart on the left according to your selection. In the chart, the values on the axes are the confidences of crimes corresponding to the labels.

3. If you want to replot the chart, you can use the "unselect button" to uncheck all the labels.

4. This section also lists the labels of the detected crimes that have 100% confidence.


Search Crimes
==========================
You can use this search field to search crimes with specific strings in crime descriptions. It helps you find particular crimes quickly.


Confidence Filter
==========================
With this filter, you can view crimes at specific confidence levels.


Detected Crimes
==========================

At the bottom of this report, it shows the rule numbers, crime descriptions, and the confidence level of the crimes detected.
With this information, you can know what the sample does and how malicious the behaviors are.



