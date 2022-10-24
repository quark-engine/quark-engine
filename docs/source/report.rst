++++++++++++++++++++++++++++++++++++++++
Report
++++++++++++++++++++++++++++++++++++++++


Web Report
------------------------
You can analyze an APK sample and produce a beautiful summary report in HTML format through the following command.

::

    quark -a Ahmyth.apk -s -w test.html 

The meanings of the options:

* -a for sample file input
* -s for producing the summary report
* -w for Web Report file output

Here is a `demo <https://pulorsok.github.io/ruleviewer/web-report-demo>`_ of the Web Report. 
And the page can divide into four parts:

* Analysis Result
* Sample Information
* Radar Chart
* Detected Crimes

.. figure:: https://camo.githubusercontent.com/9e25807aa6c0173b995dd94f867c7eae461e29a61537d1791c3633d33e913041/68747470733a2f2f692e696d6775722e636f6d2f684733416738742e706e67
   :width: 60%


Analysis Result
==========================
First, this part gives you the statistics of the crimes detected by Quark.

There are two sections in this part:

1. A doughnut chart shows the ratio of the crimes with 100% confidence in all crimes detected. 

 .. figure:: https://i.imgur.com/Hb9pJLY.png 
    :width: 40%

2. Statistics of the number of crimes in different confidence levels from 0% to 100%. And the higher the level is, the more we are sure the behavior is malicious. 

 .. figure:: https://i.imgur.com/BDWL0Kd.png
    :width: 40%
    
Sample Information
==========================
Sample Information shows the basic information of the sample, including the file name, MD5 hash value, file size, and the labels of detected rules with 100% confidence. 

 .. figure:: https://i.imgur.com/GlU2j9O.png
    :width: 90%


Radar Chart
==========================
In this part, 

1. You can choose the labels you want as the dimensions to analyze in the radar chart. Or you can uncheck them all with the "Deselect all" button below.

 .. figure:: https://i.imgur.com/6eugv1r.png
    :width: 90%

2. Then, the page will plot the chart. And the values on the axes are the confidences of crimes corresponding to the labels.

.. figure:: https://i.imgur.com/Fvzl1X8.png 
    :width: 80%
   
3. It also lists the labels of the detected crimes that have 100% confidence.

.. figure:: https://i.imgur.com/IhHhRTv.png 
   :width: 90%


Detected Crimes
==========================

In this part,

1. It shows the rule numbers, crime descriptions, and the confidence of the crimes detected. 

 .. figure:: https://i.imgur.com/I7ywVAG.png

2. You can find crimes by searching specific strings in the Crime Description with  the searching field. 

 .. figure:: https://i.imgur.com/LSw70L1.png

3. Also, you can view crimes with specific confidence with the confidence filter.

 .. figure:: https://i.imgur.com/6Ob1axm.png
    :width: 30%
