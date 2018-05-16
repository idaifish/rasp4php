#!/usr/bin/env python3

import signal
import argparse
from threading import Event
from sys import exit
from time import sleep
from queue import Queue
from pathlib import Path
from ipaddress import ip_address
from logging.handlers import HTTPHandler
from urllib.parse import urlparse

import coloredlogs
import graypy

from __version__ import __VERSION__
from core.fpm import fpm
from core.log import logger
from core.hooks import *
from core.thread import HookThread, NotificationThread


# Global MQ
message_queue = Queue()


# Detach Event
detach_event = Event()


# Enabled Features
FEATURES = (
    CODE_EXECUTION,
    COMMAND_EXECUTION,
    FILE_UPLOAD,
    FILE_OPERATION,
    SSRF,
    INFO_LEAKING,
    # SQL_INJECTION,
    DESERIALIZATION,
)


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
    logger.info("OK, php-fpm {} is running".format(fpm.version))


def set_hooks():
    fpm_workers = fpm.get_current_workers()
    fpm_version = fpm.version
    fpm_modules = fpm.get_modules()
    fpm_modules_set = set(fpm_modules)

    hook_script_dir = Path(__file__).parent / 'core/hooks'
    hook_funcs = []
    for f in FEATURES:
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
    argparser = argparse.ArgumentParser(prog="rasp4php", description="RASP for PHP")
    argparser.add_argument('-v', '--version', action='version', help="Version number", version='%(prog)s {}'.format(__VERSION__))
    argparser.add_argument('--debug', action='store_true', help="Debug Mode")
    argparser.add_argument('--graylog', help="Graylog Host")
    argparser.add_argument('--graylog-port', default=12201, help="Graylog UDP Port(default: 12201)")
    argparser.add_argument('--graylog-loglevel', default='CRITICAL', help="Graylog Log Level(default: CRITICAL)")
    argparser.add_argument('--webhook', help="Webhook URL(eg: http://127.0.0.1:8080/webhooks)")


    args = argparser.parse_args()

    if args.debug:
        coloredlogs.install(
            level='DEBUG',
            logger=logger,
            fmt = '%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s'
        )

    if args.graylog:
        try:
            ip_address(args.graylog)
        except:
            argparser.error("Invalid IP Address")

        graylog_handler = graypy.GELFHandler(args.graylog, args.graylog_port, debugging_fields=False)
        graylog_handler.setLevel(args.graylog_loglevel)
        logger.addHandler(graylog_handler)

    if args.webhook:
        parsed_webhook = urlparse(args.webhook)
        webhook_handler = HTTPHandler(parsed_webhook.netloc, parsed_webhook.path, method='POST', secure=False, credentials=None, context=None)
        webhook_handler.setLevel("CRITICAL")
        logger.addHandler(webhook_handler)

    bootstrap()

    # Signal
    signal.signal(signal.SIGINT, exit_callback)
    signal.signal(signal.SIGTERM, exit_callback)

    set_hooks()


if __name__ == '__main__':
    main()