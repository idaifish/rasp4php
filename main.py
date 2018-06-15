#!/usr/bin/env python3

import argparse
from logging.handlers import HTTPHandler
from urllib.parse import urlparse

import graypy
import coloredlogs

from rasp.common.version import __VERSION__
from rasp.core.log import logger, RedisHandler
from rasp.core.app import Application


def main():
    argparser = argparse.ArgumentParser(prog=Application.name, description="RASP for PHP")
    argparser.add_argument('-v', '--version', action='version', help="Version number", version='%(prog)s {}'.format(__VERSION__))
    argparser.add_argument('--debug', action='store_true', help="Debug Mode")
    argparser.add_argument('--graylog-host', help="Graylog Host")
    argparser.add_argument('--graylog-port', default=12201, help="Graylog UDP Port(default: 12201)")
    argparser.add_argument('--graylog-loglevel', default='CRITICAL', help="Graylog Log Level(default: CRITICAL)")
    argparser.add_argument('--webhook', help="Webhook URL(eg: http://127.0.0.1:8080/webhooks)")
    argparser.add_argument('--redis-host', help="Redis Host")
    argparser.add_argument('--redis-port', default=6379, help="Redis Port")
    argparser.add_argument('--redis-db', default=0, help="Redis Database")
    argparser.add_argument('--redis-password', help="Redis Password")
    argparser.add_argument('--redis-channel', help="Redis Publish/Subscribe channel")

    args = argparser.parse_args()
    app = Application()

    if args.debug:
        coloredlogs.install(
            level='DEBUG',
            logger=logger,
            fmt='%(asctime)s %(levelname)-8s [%(name)s:%(threadName)s] %(message)s'
        )

    if args.graylog_host:
        graylog_handler = graypy.GELFHandler(args.graylog_host, args.graylog_port, debugging_fields=False)
        graylog_handler.setLevel(args.graylog_loglevel)
        logger.addHandler(graylog_handler)

    if args.webhook:
        parsed_webhook = urlparse(args.webhook)
        webhook_handler = HTTPHandler(parsed_webhook.netloc, parsed_webhook.path, method='POST', secure=False, credentials=None, context=None)
        webhook_handler.setLevel("CRITICAL")
        logger.addHandler(webhook_handler)

    if args.redis_host:
        redis_handler = RedisHandler(args.redis_channel, args.redis_host, args.redis_port, args.redis_db, args.redis_password)
        redis_handler.setLevel("CRITICAL")
        logger.addHandler(redis_handler)

    # Start RASP4PHP
    app.start()


if __name__ == '__main__':
    main()