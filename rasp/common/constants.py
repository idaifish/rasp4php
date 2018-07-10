from __future__ import unicode_literals
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path


PROJECT_ROOT = Path(__file__).parent.parent.parent
