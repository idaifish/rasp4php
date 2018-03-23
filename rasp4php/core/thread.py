import logging
from threading import Thread

import frida

from json import loads


logger = logging.getLogger('rasp4php')


class HookThread(Thread):
    """Hook PHP-FPM workers.
    """

    def __init__(self, worker_pid, hooks, message_queue):
        super().__init__()
        self.worker_pid = worker_pid
        self.name = "HookThread-{}".format(str(worker_pid))
        self.hooks = hooks
        self.message_queue = message_queue
        self.session = None

    def run(self):
        try:
            logger.info("Starting to hook php-fpm worker: {}".format(str(self.worker_pid)))
            self.session = frida.attach(self.worker_pid)

            if self.session:
                logger.info("PHP-FPM Worker: {} is attached".format(str(self.worker_pid)))
        except Exception as e:
            logger.exception(e)

        for hook_name in self.hooks:
            logger.debug("Setting hook '{}' for {}".format(hook_name, self.name))

            with open(hook_name) as hook_script:
                func_name = hook_name.split('/')[-1].strip('.js')
                hook = """
                send("Function {func_name} is hooked successfully");
                Interceptor.attach(Module.findExportByName(null, '{func_name}'), {hook_script});
                """.format(func_name=func_name, hook_script=hook_script.read())
                script = self.session.create_script(hook)
                script.on('message', lambda message, data: self.message_queue.put(message))
                script.load()


class NotificationThread(Thread):
    """Read Message Queue
    """

    def __init__(self, message_queue):
        super().__init__()
        self.message_queue = message_queue
        self.name = "NotificationThread"

    def run(self):
        logger.info("Notification Thread is starting.")

        while True:
            message = self.message_queue.get()

            if message['type'] == 'send':
                logger.debug(message['payload'])
            elif message['type'] == 'error':
                logger.error(message['stack'])
