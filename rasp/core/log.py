import logging
import logging.config
from json import dumps

import redis


LOGGING = {
    "version": 1,
    "formatters": {
        "default": {
            "format": '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s',
            "datefmt": '%Y-%m-%d %H:%M:%S'
        }
    },
    "filters": {},
    "handlers": {
        "develop": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "stream": 'ext://sys.stdout',
            "formatter": "default"
        },
        "production": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "filename": "/tmp/rasp4php.log",
            "formatter": "default",
            "maxBytes": 4096
        },
    },
    "loggers": {
        "rasp4php": {
            "handlers": ["develop", "production"],
            "level": "INFO"
        }
    }
}


# Global logger
logging.config.dictConfig(LOGGING)
logging.raiseExceptions = False
logger = logging.getLogger('rasp4php')


# Redis Handler
class RedisFormatter(logging.Formatter):
    """Redis Message JSON Formatter."""

    def __init__(self):
        super().__init__(self)

    def format(self, record):
        data = record.__dict__.copy()

        if 'exc_info' in data and data['exc_info']:
            data['exc_info'] = self.formatException(data['exc_info'])

        return dumps(data)


class RedisHandler(logging.Handler):
    """Publish message to redis channel."""

    def __init__(self, channel, host='localhost', port=6379, db=0, password=None, level=logging.NOTSET, formatter=RedisFormatter):
        self.channel = channel
        self.level = level
        self.formatter = formatter
        self.redis_client = redis.StrictRedis(host, port, db, password)
        super().__init__(self.level)

    def emit(self, record):
        try:
            self.redis_client.publish(self.channel, self.format(record))
        except redis.RedisError:
            pass