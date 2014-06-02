"""
Avoid depending on any particular Python 3 compatibility approach.
"""

import sys


PY3 = sys.version_info[0] == 3
if PY3:  # pragma: nocover
    text_type = str
else:
    text_type = unicode
