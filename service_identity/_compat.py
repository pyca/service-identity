"""
Avoid depending on any particular Python 3 compatibility approach.
"""

import sys


PY3 = sys.version_info[0] == 3
if PY3:  # pragma: nocover
    text_type = str

    def u(s):
        return s
else:
    text_type = unicode

    def u(s):
        return unicode(s.replace(r'\\', r'\\\\'), "unicode_escape")
