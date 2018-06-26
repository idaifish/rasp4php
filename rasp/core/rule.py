from configparser import ConfigParser
from os.path import expanduser

from rasp.common.constants import PROJECT_ROOT
from rasp.core.log import logger


class RuleManager(object):
    """Managing rules"""

    DEFAULT_RULE_DIR = PROJECT_ROOT / "rasp/rules"
    rule = ConfigParser(allow_no_value=True, delimiters=('=',))

    def __init__(self):
        self.load_rules()

    def load_rules(self):
        rule_path = [f.as_posix() for f in self.DEFAULT_RULE_DIR.glob('*')]
        user_rule_path = expanduser("~/.rasp.rule")
        rule_path.append(user_rule_path)
        logger.info("Loading filter rule from {}".format(self.rule.read(rule_path)))

    def get_rule(self, section):
        if self.rule.has_section(section):
            return self.rule[section]

    def dump_rules(self, path=None):
        if path is not None:
            self.rule.write(open(path, 'w'))
