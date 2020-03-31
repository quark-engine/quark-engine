from quark.androguard.core.analysis.analysis import Analysis
from quark.androguard.core.bytecodes.apk import APK
from quark.androguard.core.bytecodes.dvm import DalvikVMFormat


def AnalyzeAPK(_file, raw=False):
    """
    Analyze an android application and setup all stuff for a more quickly
    analysis!
    If session is None, no session is used at all. This is the default
    behaviour.
    If you like to continue your work later, it might be a good idea to use a
    session.
    A default session can be created by using :meth:`~get_default_session`.

    :param _file: the filename of the android application or a buffer which represents the application
    :type _file: string (for filename) or bytes (for raw)
    :param session: A session (default: None)
    :param raw: boolean if raw bytes are supplied instead of a filename
    :rtype: return the :class:`~androguard.core.bytecodes.apk.APK`, list of :class:`~androguard.core.bytecodes.dvm.DalvikVMFormat`, and :class:`~androguard.core.analysis.analysis.Analysis` objects
    """

    a = APK(_file, raw=raw)
    # FIXME: probably it is not necessary to keep all DalvikVMFormats, as
    # they are already part of Analysis. But when using sessions, it works
    # this way...
    d = []
    dx = Analysis()
    for dex in a.get_all_dex():
        df = DalvikVMFormat(dex, using_api=a.get_target_sdk_version())
        dx.add(df)
        d.append(df)

    dx.create_xref()

    return a, d, dx
