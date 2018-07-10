from __future__ import unicode_literals
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

from builtins import super

from rasp.core.filter import AbstractFilter, FilterResult, FilterContext


class DefaultScriptFileFilter(AbstractFilter):
    """Filtering message by script file.

    Syntax:
        [default.script.whitelist]
        "filename:lineno"   # e.g. /path/to/ignore_eval.php:233
        "folder_name"       # e.g. /path/to/wp-includes/
    """

    name = 'DefaultScriptFileFilter'
    context = FilterContext.ANY
    rule_entries = (
        'default.script.whitelist',
    )

    def __init__(self, rule=None):
        super().__init__(rule)

    def is_whitelisted(self, filename):
        if self.rule['default.script.whitelist']:
            for whitelisted_file in self.rule['default.script.whitelist']:
                whitelisted_file = Path(whitelisted_file)
                if whitelisted_file.is_dir():
                    if whitelisted_file in Path(filename).parents:
                        return True
                else:
                    if whitelisted_file == filename:
                        return True

        return False

    def filter(self, message):
        if 'filename' not in message or 'lineno' not in message:
            return FilterResult.DEFAULT

        suspicious_file = ":".join((message['filename'], str(message['lineno'])))

        if self.is_whitelisted(suspicious_file):
            return FilterResult.IGNORE

        return FilterResult.DEFAULT
