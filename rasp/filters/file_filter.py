from urllib.parse import urlparse

from rasp.core.filter import AbstractFilter, FilterResult, FilterContext


class DefaultFileFilter(AbstractFilter):
    """File access filtering.

    Syntax:
        [default.file.whitelist]
        'filename'
        'folder_name'

        [default.file.blacklist]
        'filename'
        'folder_name'
    """

    name = 'DefaultFileFilter'
    context = FilterContext.FILE
    rule_entries = (
        'default.file.whitelist',
        'default.file.blacklist',
    )

    def __init__(self, rule: dict=None):
        super().__init__(rule)

    def is_whitelisted(self, filename) -> bool:
        if self.rule['default.file.whitelist']:
            for f in self.rule['default.file.whitelist']:
                if f in filename:
                    return True

        return False

    def is_blacklisted(self, filename) -> bool:
        if self.rule['default.file.blacklist']:
            for f in self.rule['default.file.blacklist']:
                if f in filename:
                    return True

        return False

    def has_suspicious_scheme(self, filename) -> bool:
        urlparsed_result = urlparse(filename)

        if urlparsed_result.scheme in ('data', 'php', 'expect'):
            return True

        return False

    def has_file_scheme(self, filename) -> bool:
        urlparsed_result = urlparse(filename)

        if urlparsed_result.scheme in ('', 'file'):
            return True

        return False

    def filter(self, message):
        for file_accessed in message['args']:
            if self.has_suspicious_scheme(file_accessed):
                return FilterResult.ALERT

            if self.has_file_scheme(file_accessed):
                for normalized_filename in message['normalized_args']:
                    if self.is_blacklisted(normalized_filename):
                        return FilterResult.ALERT

                    if self.is_whitelisted(normalized_filename):
                        return FilterResult.IGNORE
            else:
                # Other schemes will be ignored
                return FilterResult.IGNORE

        return FilterResult.DEFAULT
