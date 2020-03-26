import hashlib
import logging

from quark.androguard.core.analysis.analysis import Analysis
from quark.androguard.core.bytecodes.apk import APK
from quark.androguard.core.bytecodes.dvm import DalvikVMFormat
from quark.androguard.decompiler import decompiler

log = logging.getLogger("androguard.misc")


def AnalyzeAPK(_file, session=None, raw=False):
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
    log.debug("AnalyzeAPK")

    if session:
        log.debug("Using existing session {}".format(session))
        if raw:
            data = _file
            filename = hashlib.md5(_file).hexdigest()
        else:
            with open(_file, "rb") as fd:
                data = fd.read()
                filename = _file

        digest = session.add(filename, data)
        return session.get_objects_apk(filename, digest)
    else:
        log.debug("Analysing without session")
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
            df.set_decompiler(decompiler.DecompilerDAD(d, dx))

        dx.create_xref()

        return a, d, dx
