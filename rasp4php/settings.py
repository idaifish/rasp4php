from core.hooks import *

VERSION = 'v0.1'

# Graylog
GRAYLOG_HOST = '127.0.0.1'
GRAYLOG_PORT = 12201

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
        "graylog": {
            "class": "graypy.GELFHandler",
            "level": "CRITICAL",
            "host": GRAYLOG_HOST,
            "port": GRAYLOG_PORT,
            "debugging_fields": False
        },
    },
    "loggers": {
        "rasp4php": {
            "handlers": ["develop", "production", "graylog"],
            "level": "INFO"
        }
    }
}

# Enabled Features
FEATURES = (
    CODE_EXECUTION,
    COMMAND_EXECUTION,
    FILE_UPLOAD,
    FILE_OPERATION,
    # SSRF,
    INFO_LEAKING,
    # SQL_INJECTION,
    DESERIALIZATION,
)