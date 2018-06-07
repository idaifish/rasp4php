import re
from pathlib import Path


# Filter Rules
DEFAULT_RULE = {
    "whitelist": {
        # Script File
        # Syntax:
        #   1. scriptfile:lineno
        #   2. folder
        "script_filename": [
            # eg: 'ignore_eval.php:2333'
            # eg: '/var/www/html/cms/wordpress/',
        ],

        # File Access
        # Syntax:
        #    1. filename
        #    2. folder
        "file": [
            # eg: '/var/run',
        ],

        # Network Access
        # Syntax:
        #    scheme://netloc/path:port
        "url": [
            # eg: 'https://api.wordpress.org',
            'unix:///var/run/mysqld/mysqld.sock',
        ]
    }
}


class FilterManager(object):

    def __init__(self):
        self.filters = []

    def load_rule(self):
        self.rules = DEFAULT_RULE

    def load_filters(self):
        # Parse rule
        whitelist = self.rules['whitelist']

        if 'script_filename' in whitelist:
            self.filters.append(FilenameFilter(whitelist['script_filename']))

        if 'file' in whitelist:
            self.filters.append(FileAccessFilter(whitelist['file']))

        if 'url' in whitelist:
            self.filters.append(NetworkAccessFilter(whitelist['url']))

    def filter(self, message) -> bool:
        try:
            result = [filter.filter(message) for filter in self.filters]
        except:
            raise Exception("filter error")
            #return True

        return all(result)


class Filter(object):
    """Filter base class.
    """
    def __init__(self, rule):
        self.rule = rule

    def filter(self, message) -> bool:
        pass


class FilenameFilter(Filter):

    def __init__(self, rule):
        super().__init__(rule)

    def filter(self, message) -> bool:
        if 'filename' not in message:
            return True

        whitelisted_file = ":".join((message['filename'], str(message['lineno'])))

        if whitelisted_file in self.rule:
            return False

        for filename in self.rule:
            if Path(filename) in Path(message['filename']).parents:
                return False

        return True


class FileAccessFilter(Filter):
    """File access whitelist.
    """
    def __init__(self, rule):
        super().__init__(rule)

    def filter(self, message) -> bool:
        if 'args' not in message:
            return True

        for file_accessed in message['args']:
            file_accessed_path = Path(file_accessed)

            for f in self.rule:
                whitelisted_file = Path(f)
                if whitelisted_file.is_dir():
                    if whitelisted_file in file_accessed_path.parents:
                        return False
                else:
                    if file_accessed_path.samefile(whitelisted_file.resolve()):
                        return False

        return True


class NetworkAccessFilter(Filter):
    def __init__(self, rule):
        super().__init__(rule)

    def filter(self, message) -> bool:
        if 'args' not in message:
            return True

        for url_accessed in message['args']:
            # TODO: check ip
            if url_accessed in self.rule:
                return False

        return True
