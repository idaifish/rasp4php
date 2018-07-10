from __future__ import unicode_literals
from sys import platform
from os import geteuid
from sys import exit

from builtins import super

from rasp.core.log import logger


class Runtime(object):
    _instance = None

    def __new__(cls):
        if not isinstance(cls._instance, cls):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        self.environment = {}
        self.environment['platform'] = platform

        self.check_permission()

    def check_permission(self):
        self.environment['euid'] = geteuid()
        if self.environment['euid'] != 0:
            logger.error("Sorry, you need root permissions/SUDO to run this app.")
            exit(-1)
