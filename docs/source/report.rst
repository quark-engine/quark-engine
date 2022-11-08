++++++++++++++++++++++++++++++++++++++++
Report
++++++++++++++++++++++++++++++++++++++++


Web Report
------------------------


This report aims to provide an easy-to-read overview of the analysis result of the APK file.

We can analyze an APK file and produce a reader-friendly summary report in HTML format with the command below.:


.. code-block:: text

    quark -a Ahmyth.apk -s -w test.html


The usage of the options:


.. code-block:: text

    -a     specifies an APK file
    -s     for summary report
    -w     generates the web report


The image below depicts the appearance of the generated Web Report. You can also check this `demo <https://pulorsok.github.io/ruleviewer/web-report-demo>`_. 

.. figure:: https://camo.githubusercontent.com/9e25807aa6c0173b995dd94f867c7eae461e29a61537d1791c3633d33e913041/68747470733a2f2f692e696d6775722e636f6d2f684733416738742e706e67
   :width: 90%


The followings are the detailed descriptions of the Web Report. 


Doughnut Chart
==========================

The doughnut chart illustrates the proportion of the crimes with 100% confidence in all crimes detected in the sample. And the fraction number is shown directly in the center of the chart. The feature helps users understand the overall maliciousness in the sample file at first glance.

Statistics of Crimes
==========================

The statistics show the number of crimes in different confidence levels from 0% to 100%. The higher the level is, the more we are sure the behavior is malicious. And the icons of levels are separated by different colors. Here, we can know the distributions of the malice of the sample.

    
Sample Information
=================================
Sample Information exhibits the basic information of the sample, including the file name, MD5 hash value, file size, and the labels of detected rules with 100% confidence. 

The first three pieces of information give identifications of the file. We can use them to find other analyses of the same file on the Internet, then compare the differences.

And with the labels of 100% confidence, we can roughly see the malicious behavior in the sample. Or we can compare them between different sample files.


Label Selecting Area
===========================
Detected labels are presented here. We can choose the labels we want as the dimensions in the radar chart by clicking the check box of each label. Then, the page will plot the radar chart according to our selection. 

If we want to replot the chart, we can easily use the “unselect button” to uncheck all the labels.


Radar Chart
==========================
The radar chart presents relations of the confidence level between different labels. With a radar chart, we can quickly find outliers that differ significantly from other dimensions. And we can also use radar charts to compare the similarity between different samples.


Labels of 100% confidence 
==============================
Here it lists the labels of the detected crimes that have 100% confidence again.

Search Crimes
==========================
We can use the Search Crime field to search crimes with specific strings in crime descriptions. It helps find particular crimes quickly.

Confidence Filter
==========================
We can filter crimes at specific confidence levels with Confidence Filter. For example, we can see only crime with 60% confidence if we set the filter to 60%.

Detected Crimes
==========================
The rule numbers, crime descriptions, and the confidence level of the detected crimes are shown in this section. With this information, we can know what the sample does and how malicious the behaviors are. If we want to dig into the detail of the crime, we can use rule numbers to look up Quark Rules. 





