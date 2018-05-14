import logging.config


LOGGING = {
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
logger = logging.getLogger('rasp4php')