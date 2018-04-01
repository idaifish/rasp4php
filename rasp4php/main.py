#!/usr/bin/env python3

import signal
import logging.config
from threading import Event
from sys import exit
from time import sleep
from queue import Queue
from itertools import chain
from pathlib import Path

import coloredlogs

import settings
from core.fpm import fpm
from core.thread import HookThread, NotificationThread


# Global MQ
message_queue = Queue()


# Detach Event
detach_event = Event()


# Logging
logging.config.dictConfig(settings.LOGGING)
logger = logging.getLogger('rasp4php')
if settings.DEBUG:
    coloredlogs.install(
        level='DEBUG',
        logger=logger,
        fmt = '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s'
    )


def exit_callback(signum, frame):
    detach_event.set()
    logger.info("RASP4PHP is exiting")
    exit(0)


def init():
    logger.info("Checking whether the php-fpm is running . . .")

    if not fpm.is_running():
        logger.error("php-fpm is not running")
        exit(-1)
    logger.info("OK, php-fpm is running")

    # Check FPM configuration
    # TODO


def set_hooks():
    fpm_workers = fpm.get_current_workers()
    fpm_version = fpm.version

    # Check settings
    hook_script_dir = Path('./core/hooks')
    features = [ set(f.values()) for f in settings.FEATURES]
    enabled_hooks = chain.from_iterable(features)
    hooks = [str(hook_script_dir / fpm_version / (hook+".js")) for hook in enabled_hooks]

    # Start threads
    NotificationThread(message_queue).start()

    for worker_pid in fpm_workers:
        HookThread(worker_pid, hooks, message_queue, detach_event).start()
        sleep(1)


def main():
    logger.info("RASP4PHP is starting.")
    signal.signal(signal.SIGINT, exit_callback)

    init()
    set_hooks()


if __name__ == '__main__':
    main()
