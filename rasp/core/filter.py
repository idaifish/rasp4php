import importlib.util
import inspect
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

from rasp.core.log import logger
from rasp.core.rule import RuleManager
from rasp.common.constants import PROJECT_ROOT


class FilterResult(Enum):
    """Filter result enumeration."""

    IGNORE = False
    ALERT = True
    DEFAULT = True


class FilterContext(Enum):
    """Filter context enumeration."""

    CODE = "code"
    COMMAND = "command"
    URL = "url"
    FILE = "file"
    SQL = "sql"
    VAR = "var"
    XXE = "xxe"
    ANY = "any"


class AbstractFilter(ABC):
    """Base class for creating a filter."""

    name = 'AbstractFilter'
    context = FilterContext.ANY
    rule_entries = ()            # Section name in the rule file

    def __init__(self, rule: dict=None):
        self.rule = rule
        logger.info("Filter '{}' is loaded.".format(self.name))

    @abstractmethod
    def filter(self, message) -> FilterResult:
        return FilterResult.DEFAULT


class FilterManager(object):
    """Managing filters."""

    DEFAULT_FILTER_DIR = PROJECT_ROOT / 'rasp/filters'

    def __init__(self, filter_path=None):
        self.rule_manager = RuleManager()
        self.filters = defaultdict(list)
        self.load_filters(filter_path)

    def load_filters(self, path=None):
        filter_paths = [self.DEFAULT_FILTER_DIR, ]
        if path is not None:
            filter_paths.append(path)

        for filter_path in filter_paths:
            for filter_file in filter_path.resolve().rglob('*.py'):
                spec = importlib.util.spec_from_file_location(filter_file.stem, filter_file.as_posix())
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for member_name, member_obj in inspect.getmembers(module):
                    if inspect.isclass(member_obj) \
                            and issubclass(member_obj, AbstractFilter) \
                            and member_obj is not AbstractFilter:
                        filter_class = member_obj
                        filter_instance = self.init_filter(filter_class)
                        self.filters[filter_instance.context].append(filter_instance)

    def get_filters(self, context: FilterContext) -> list:
        return self.filters[FilterContext.ANY] + self.filters[context]

    def init_filter(self, filter_class: AbstractFilter):
        rule = {}
        for entry in filter_class.rule_entries:
            rule[entry] = self.rule_manager.get_rule(entry)

        return filter_class(rule)

    def filter(self, message) -> bool:
        try:
            filters = self.get_filters(FilterContext(message['context']))
            result = [filter.filter(message).value for filter in filters]
        except Exception as e:
            logger.error("Failed to filter message: {}, due to {}".format(message, e))
            return FilterResult.DEFAULT.value

        return all(result)
