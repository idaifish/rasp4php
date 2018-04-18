#!/usr/bin/env python3

import signal
import argparse
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


def exit_callback(signum, frame):
    detach_event.set()
    logger.info("RASP4PHP is exiting")
    exit(0)


def bootstrap():
    logger.info("RASP4PHP is starting.")

    logger.info("Checking whether the php-fpm is running . . .")
    if not fpm.is_running():
        logger.error("php-fpm is not running")
        exit(-1)
    logger.info("OK, php-fpm is running")


def set_hooks():
    fpm_workers = fpm.get_current_workers()
    fpm_version = fpm.version
    fpm_modules = fpm.get_modules()
    fpm_modules_set = set(fpm_modules)

    # Check settings
    hook_script_dir = Path('./core/hooks')
    hook_funcs = []
    for f in settings.FEATURES:
        for k,v in f.items():
            if v['depends'].issubset(fpm_modules_set):
                hook_funcs.append(v['hook'])
    hooks = [str(hook_script_dir / fpm_version / (hook + ".js")) for hook in set(hook_funcs)]

    # Start threads
    NotificationThread(message_queue).start()

    for worker_pid in fpm_workers:
        HookThread(worker_pid, hooks, message_queue, detach_event).start()
        sleep(1)


def main():
    bootstrap()

    # Signal
    signal.signal(signal.SIGINT, exit_callback)
    signal.signal(signal.SIGTERM, exit_callback)

    set_hooks()


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(prog="rasp4php", description="RASP for PHP")
    argparser.add_argument('-v', '--version', action='version', help="Version number.", version='%(prog)s {}'.format(settings.VERSION))
    argparser.add_argument('--debug', action='store_true', help="Debug Mode.")

    args = argparser.parse_args()

    if args.debug:
        coloredlogs.install(
            level='DEBUG',
            logger=logger,
            fmt = '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s'
        )

    main()
