#!/usr/bin/env python3

from sys import exit
from glob import glob
from time import sleep
from queue import Queue

import fpm
import thread
from log import logger


# Global MQ
message_queue = Queue()

def main():
    if not fpm.is_alive():
        logger.error("php-fpm is not running")
        exit(-1)

    fpm_workers = fpm.get_current_workers()
    fpm_version = fpm.get_version()
    hooks = glob("hooks/" + fpm_version + "/*.js")

    for worker_pid in fpm_workers:
        thread.HookThread(worker_pid, hooks, message_queue).start()
        sleep(1)

    thread.NotificationThread(message_queue).start()


if __name__ == '__main__':
    main()
