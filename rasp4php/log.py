import logging.config

import coloredlogs


CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s',
            "datefmt" : '%Y-%m-%d %H:%M:%S'
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
            "level": "INFO",
            "filename": "/tmp/rasp4php.log",
            "maxBytes": 4096
        }
    },
    "loggers": {
        "rasp4php": {
            "handlers": ["develop",],
            "level": "DEBUG"
        }
    }
}


logging.config.dictConfig(CONFIG)
logger = logging.getLogger("rasp4php")
coloredlogs.install(
    level='DEBUG',
    logger=logger,
    fmt = '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s'
)