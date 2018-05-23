from threading import Thread
from json import dumps

import frida

from .log import logger


class HookThread(Thread):
    """Hook PHP-FPM workers.
    """

    def __init__(self, worker_pid, hooks, message_queue, detach_event):
        super().__init__()
        self.worker_pid = worker_pid
        self.name = "HookThread-{}".format(str(worker_pid))
        self.hooks = hooks
        self.message_queue = message_queue
        self.session = None
        self.detach_event = detach_event

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
                Interceptor.attach(Module.findExportByName(null, '{func_name}'), {hook_script});
                send("HookThread-{worker_pid}: Function {func_name} is hooked successfully");
                """.format(func_name=func_name, hook_script=hook_script.read(), worker_pid=self.worker_pid)
                script = self.session.create_script(hook)
                script.on('message', lambda message, data: self.message_queue.put(message))
                script.load()

        self.detach_event.wait()
        logger.info("PHP-FPM Worker: {} is detached".format(str(self.worker_pid)))
        self.session.detach()


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
                if isinstance(message['payload'], str):
                    logger.debug(message['payload'])
                else:
                    logger.critical(dumps(message['payload']))
            elif message['type'] == 'error':
                logger.debug(message['stack'])
