from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK, AnalyzeDex





class x_rule:

    def __init__(self, apk):
        self.a, self.d, self.dx = AnalyzeAPK(apk)

    @property
    def permissions(self):
        return self.a.get_permissions()


data = x_rule('14d9f1a92dd984d6040cc41ed06e273e.apk')


print(data.permissions)
