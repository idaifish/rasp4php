from core.hooks import *

VERSION = 0.1
DEBUG = True

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
            "level": "INFO",
            "filename": "/tmp/rasp4php.log",
            "formatter": "default",
            "maxBytes": 4096
        }
    },
    "loggers": {
        "rasp4php": {
            "handlers": ["develop","production"],
            "level": "INFO"
        }
    }
}

# Enabled Features
FEATURES = (
    CODE_EXECUTION,
    COMMAND_EXECUTION,
    FILE_UPLOAD,
    # FILE_INCLUSION,
    # FILE_READ_WRITE,
    # SSRF,
    INFO_LEAKING,
    # SQL_INJECTION,
    DESERIALIZATION,
)