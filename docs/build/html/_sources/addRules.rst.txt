+++++++++
Add Rules
+++++++++

Android malware analysis engine is not a new story. Every antivirus company has
their own secrets to build it. With curiosity, we develop a malware scoring
system from the perspective of Taiwan Criminal Law in an easy but solid way.

We have an order theory of criminal which explains stages of committing a crime.
For example, crime of murder consists of five stages, they are determined,
conspiracy, preparation, start and practice. The latter the stage the more
we’re sure that the crime is practiced.

According to the above principle, we developed our order theory of android
malware. We develop five stages to see if the malicious activity is being
practiced. They are

    1. Permission requested.
    2. Native API call.
    3. Certain combination of native API.
    4. Calling sequence of native API.
    5. APIs that handle the same register.

We not only define malicious activities and their stages but also develop
weights and thresholds for calculating the threat level of a malware.

But before we explain how to set weights and thresholds, we need to define
crimes and corresponding five stages.

An example of defining crime "Send Location via SMS" is shown below. We use
json format to construct the rule of the crime.

.. code-block:: python
   :linenos:

   {
        "crime": "Send Location via SMS",

        "x1_permission": [
            "android.permission.SEND_SMS",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION"
        ],

        "x2n3n4_comb": [
            {
                "class": "Landroid/telephony/TelephonyManager",
                "method": "getCellLocation"
            },
            {
                "class": "Landroid/telephony/SmsManager",
                "method": "sendTextMessage"
            }
        ],

        "yscore": 4
   }


So let me walk you through the json file.

.. code-block:: python

   "crime": "Send Location via SMS"

First, we define the crime. Our principle of constructing a crime is
``Action + Target``. In this example, the action is "Send SMS" and the target
is Location info. Therefore, the crime of our first rule is defined as:
"Send Location via SMS".


.. code-block:: python

  "x1_permission": [
        "android.permission.SEND_SMS",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION"
  ]

``x1_permission`` is where we fill in permission requested by the apk to
practice the crime. For instance, we need permission
``android.permission.SEND_SMS`` to send information through SMS. We also need
permission ``android.permission.ACCESS_COARSE_LOCATION`` and
``android.permission.ACCESS_FINE_LOCATION`` to practice the crime.

.. code-block:: python

  "x2n3n4_comb": [
        {
            "class": "Landroid/telephony/TelephonyManager",
            "method": "getCellLocation"
        },
        {
            "class": "Landroid/telephony/SmsManager",
            "method": "sendTextMessage"
        }
  ]

``x2n3n4_comb`` means this field can be used to practice analysis from
stage 2 to stage 4.

In stage 2, we need to find key native APIs that do
the ``Action`` and ``Target``. And since the API method name can be used by
self-defined class. We need to fill in information of both the native
API class name and method name.

.. note:: We like to keep our crime/rule simple. So do not fill in more than 2 native APIs.

In stage 3, we will find the combination of the native APIs we define
in stage 2. Further, we will check whether they're called in the same method.
If so, we will say that the combination of crime is caught!
And we don't need to do anything to adjust the ``x2n3n4_comb`` field.

.. note:: We know that the native API might be wrapped in other methods. We use XREF to solve this problem.

In stage 4, we will find whether the native APIs are called in a right sequence.
If so, we have more confidence that the crime is practiced.

.. note:: Please place the APIs in the order as the crime is being committed.

In stage 5, we will check whether the native APIs are operating the same parameter.
If so, we are 100% sure that the crime is practiced.

As for the field ``yscore``, we will be updating our principles of weight defining.
please check that part later.
