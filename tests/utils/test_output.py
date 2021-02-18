import pytest
import requests

from quark.utils.output import output_parent_function_table
from quark.Objects.quark import Quark

APK_SOURCE = "https://github.com/quark-engine/apk-malware-samples" \
             "/raw/master/14d9f1a92dd984d6040cc41ed06e273e.apk"
APK_FILENAME = "14d9f1a92dd984d6040cc41ed06e273e.apk"


@pytest.fixture()
def quark_obj(scope="function"):
    r = requests.get(APK_SOURCE, allow_redirects=True)
    open(APK_FILENAME, "wb").write(r.content)

    return Quark(APK_FILENAME)


def test_output_parent_function_table(capsys, quark_obj):
    method_obj = quark_obj.apkinfo.find_method(
        'Lcom/google/progress/WifiCheckTask;', 'goConnectNetwork', '()V')

    call_graph_analysis_list = ({
        'crime': 'The Crime',
        'parent': method_obj
    }, {
        'crime': 'The Crime',
        'parent': method_obj
    }, {
        'crime': 'Another Crime',
        'parent': method_obj
    })

    # Test one crime
    output_parent_function_table([call_graph_analysis_list[0]])

    output = capsys.readouterr().out
    assert output.count(
        'Lcom/google/progress/WifiCheckTask;goConnectNetwork') == 1
    assert output.count('The Crime') == 1

    # Test crimes with duplicated description
    output_parent_function_table(call_graph_analysis_list)

    output = capsys.readouterr().out
    print(output)
    assert output.count(
        'Lcom/google/progress/WifiCheckTask;goConnectNetwork') == 1
    assert output.count('The Crime') == 1
    assert output.count('Another Crime') == 1
