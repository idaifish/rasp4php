import signal
from sys import exit
from threading import Event

from rasp.core.log import logger
from rasp.core.fpm import fpm
from rasp.core.runtime import runtime
from rasp.core.hooks import HooksManager
from rasp.core.message import message_queue
from rasp.core.thread import HookMasterThread, HookWorkerThread, NotificationThread


class Application(object):

    name = "RASP4PHP"

    def __init__(self, mode="monitoring"):
        self.mode = mode
        self.environment = runtime.environment
        self.detach_event = Event()

    def bootstrap(self):
        logger.info("{} is starting.".format(self.name))

        logger.info("Checking whether the PHP-FPM is running . . .")
        if not fpm.is_running():
            logger.error("PHP-FPM is not running")
            exit(-1)
        logger.info("OK, PHP-FPM {} is running on {}".format(fpm.full_version, self.environment['platform']))

        self.environment['rasp_mode'] = self.mode

        # Get phpinfo
        self.environment['fpm_master'] = fpm.get_master()
        self.environment['fpm_workers'] = fpm.get_current_workers()
        self.environment['fpm_version'] = fpm.version
        self.environment['fpm_enabled_modules'] = fpm.get_modules()
        self.environment['fpm_disabled_functions'] = fpm.get_disabled_functions()
        logger.info("PHP-FPM enabled modules: {}".format(set(self.environment['fpm_enabled_modules'])))
        logger.info("PHP-FPM disabled functions: {}".format(self.environment['fpm_disabled_functions']))

    def exit_callback(self, signum, frame):
        self.detach_event.set()
        message_queue.put({'type': 'exit'})
        logger.info("{} is exiting".format(self.name))
        exit(0)

    def set_signal_handler(self):
        signal.signal(signal.SIGINT, self.exit_callback)
        signal.signal(signal.SIGTERM, self.exit_callback)

    def start_threads(self):
        notification_thread = NotificationThread()
        notification_thread.start()

        hooks = HooksManager().get_hook_scripts(self.environment)
        HookMasterThread(self.environment['fpm_master'], hooks, self.detach_event).start()

        for worker_pid in self.environment['fpm_workers']:
            HookWorkerThread(worker_pid, hooks, self.detach_event).start()

        notification_thread.join()

    def start(self):
        self.bootstrap()
        self.set_signal_handler()
        self.start_threads()
