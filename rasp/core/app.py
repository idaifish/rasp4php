import signal
from sys import exit

from rasp.core.log import logger
from rasp.core.fpm import fpm
from rasp.core.hooks import HooksManager
from rasp.core._globals import detach_event, environment, message_queue
from rasp.core.thread import HookMasterThread, HookWorkerThread, NotificationThread


class Application(object):

    name = "RASP4PHP"

    def __init__(self):
        pass

    def bootstrap(self):
        logger.info("{} is starting.".format(self.name))

        logger.info("Checking whether the PHP-FPM is running . . .")
        if not fpm.is_running():
            logger.error("PHP-FPM is not running")
            exit(-1)
        logger.info("OK, PHP-FPM {} is running on {}".format(fpm.full_version, fpm.platform))

        # Get phpinfo
        environment['fpm_master'] = fpm.get_master()
        environment['fpm_workers'] = fpm.get_current_workers()
        environment['fpm_version'] = fpm.version
        environment['fpm_enabled_modules'] = fpm.get_modules()
        environment['fpm_disabled_functions'] = fpm.get_disabled_functions()
        logger.info("PHP-FPM enabled modules: {}".format(set(environment['fpm_enabled_modules'])))
        logger.info("PHP-FPM disabled functions: {}".format(environment['fpm_disabled_functions']))

    def exit_callback(self, signum, frame):
        detach_event.set()
        message_queue.put({'type': 'exit'})
        logger.info("{} is exiting".format(self.name))
        exit(0)

    def set_signal_handler(self):
        signal.signal(signal.SIGINT, self.exit_callback)
        signal.signal(signal.SIGTERM, self.exit_callback)

    def start_threads(self):
        notification_thread = NotificationThread()
        notification_thread.start()

        hooks = HooksManager().get_hook_scripts(environment)
        HookMasterThread(environment['fpm_master'], hooks, detach_event).start()

        for worker_pid in environment['fpm_workers']:
            HookWorkerThread(worker_pid, hooks, detach_event).start()

        notification_thread.join()

    def start(self):
        self.bootstrap()
        self.set_signal_handler()
        self.start_threads()
