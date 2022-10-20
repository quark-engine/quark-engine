++++++++++++++++++++++++++++++++++++++++
Report
++++++++++++++++++++++++++++++++++++++++


Web Report
------------------------
You can analyze an APK sample and produce a beautiful summary report in HTML format with the following command.

::

    quark -a Ahmyth.apk -s -w test.html 

the meanings of the options:

* -a for sample file input
* -s for producing the summary report
* -w for Web Report file output

Here is a `demo <https://pulorsok.github.io/ruleviewer/web-report-demo>`_ of the Web Report. 
And the page can be divided into four parts:

* Analysis Result
* Sample Information
* Radar Chart
* Detected Crimes

.. figure:: https://camo.githubusercontent.com/9e25807aa6c0173b995dd94f867c7eae461e29a61537d1791c3633d33e913041/68747470733a2f2f692e696d6775722e636f6d2f684733416738742e706e67
   :width: 60%


Analysis Result
==========================
First, Analysis Result gives you the statics of the crimes detected by Quark.

You can see the following:

1. There is a doughnut chart on the left, showing the ratio of the crimes with 100% confidence in all crimes detected. 

2. On the right of the doughnut chart, you can see the number of crimes in different confidence levels. The confidence levels are 0%, 20%, 40%, 60%, 80% and 100%. The higher the level is, the more we are sure the behavior is malicious. 

 .. figure:: https://i.imgur.com/XkkaCvJ.png
    :width: 90%
    
Sample Information
==========================
This part shows the basic information of the sample, including file name, MD5 hash value, file size, and labels of detected rules with 100% confidence. 


 .. figure:: https://i.imgur.com/7hSXJDZ.png
    :width: 90%


Radar Chart
==========================
In the part of the Radar Chart, 

1. You can easily choose the labels you want on the right. And they will be the dimensions to analyze in the radar chart.

2. Then, the page will draw the chart on the left. And the values on the axes are the confidences of crimes corresponding to the labels. 

3. If you decide to draw the chart all over again, you can use the deselect button to uncheck all the labels.

4. Also, the labels of the crimes detected with 100% confidence are displayed.

 .. figure:: https://i.imgur.com/TDiadQZ.png
    :width: 90%


Detected Crimes
==========================

In this part,

1. It shows the rule numbers, crime descriptions, and the confidence of the crimes. 


 .. figure:: https://i.imgur.com/h1Ai1VZ.png
    :width: 90%

2. You can find crimes by searching specific strings in the Crime Description with the searching field. 

3. And you can show crimes with particular confidence using the drop-down list.


 .. figure:: https://i.imgur.com/n9Y3uKx.png
    :width: 90%
