from threading import Thread, Lock
from json import dumps

import frida

from ._globals import message_queue, environment
from .log import logger
from .filter import FilterManager


# Local device lock
attach_lock = Lock()


class HookMasterThread(Thread):
    """Hook PHP-FPM master.
    """

    def __init__(self, master_pid, hooks, detach_event):
        super().__init__()
        self.master_pid = master_pid
        self.name = "HookMasterThread-{}".format(str(self.master_pid))
        self.hooks = hooks
        self.message_queue = message_queue
        self.detach_event = detach_event

        try:
            logger.info("Starting to hook PHP-FPM Master-{}".format(str(self.master_pid)))
            attach_lock.acquire()
            self._device = frida.get_local_device()
            self.session = self._device.attach(self.master_pid)
            attach_lock.release()
            self.session.on('detached', self.on_detached)
            self._device.on("child-added", self.on_child_added)
            self._device.on("child-removed", self.on_child_removed)

            if self.session:
                logger.info("PHP-FPM Master-{} is attached".format(str(self.master_pid)))
        except Exception as e:
            logger.exception(e)

    def on_child_added(self, child):
        logger.info("PHP-FPM Master spawned a new worker: worker-{}".format(child.pid))
        new_child = HookWorkerThread(child.pid, self.hooks, self.detach_event, new_child=True)
        new_child.start()

    def on_child_removed(self, child):
        logger.info("PHP-FPM Master removed a worker: worker-{}".format(child.pid))

    def on_detached(self, reason):
        logger.info("PHP-FPM Master-{} is detached".format(str(self.master_pid)))

    def on_message(self, message, data):
        self.message_queue.put(message)

    def run(self):
        # pm = dynamic
        self.session.enable_child_gating()

        self.detach_event.wait()
        self.session.detach()


class HookWorkerThread(Thread):
    """Hook PHP-FPM workers.
    """

    def __init__(self, worker_pid, hooks, detach_event, new_child=False):
        super().__init__()
        self.worker_pid = worker_pid
        self.name = "HookWorkerThread-{}".format(str(worker_pid))
        self.hooks = hooks
        self.message_queue = message_queue
        self.detach_event = detach_event
        self.new_child = new_child

        try:
            logger.info("Starting to hook PHP-FPM Worker-{}".format(str(self.worker_pid)))
            attach_lock.acquire()
            self._device = frida.get_local_device()
            self.session = self._device.attach(self.worker_pid)
            attach_lock.release()
            self.session.on('detached', self.on_detached)

            if self.session:
                logger.info("PHP-FPM Worker-{} is attached".format(str(self.worker_pid)))
        except Exception as e:
            logger.exception(e)

    def on_message(self, message, data):
        self.message_queue.put(message)

    def on_detached(self, reason):
        logger.info("PHP-FPM Worker-{} is detached".format(str(self.worker_pid)))

    def instrument(self):
        for hook_name in self.hooks:
            logger.debug("Setting hook '{}' for {}".format(hook_name, self.name))

            with open(hook_name) as hook_script:
                func_name = hook_name.split('/')[-1].strip('.js')
                hook = """
                Interceptor.attach(Module.findExportByName(null, '{func_name}'), {hook_script});
                send("HookWorkerThread-{worker_pid}: Function {func_name} is hooked successfully");
                """.format(func_name=func_name, hook_script=hook_script.read(), worker_pid=self.worker_pid)
                script = self.session.create_script(hook)
                script.on('message', self.on_message)
                script.load()

    def run(self):
        self.instrument()

        # resume child
        if self.new_child:
            self._device.resume(self.worker_pid)

        self.detach_event.wait()
        self.session.detach()


class NotificationThread(Thread):
    """Read Message Queue
    """

    def __init__(self):
        super().__init__()
        self.message_queue = message_queue
        self.name = "NotificationThread"

        filter_manager = FilterManager()
        filter_manager.load_rule()
        filter_manager.load_filters()
        self.filter_manager = filter_manager

    def run(self):
        logger.info("Notification Thread is starting.")

        while True:
            message = self.message_queue.get()

            if message['type'] == 'send':
                if isinstance(message['payload'], str):
                    logger.debug(message['payload'])
                else:
                    if self.filter_manager.filter(message['payload']):
                        logger.critical(dumps(message['payload']))
            elif message['type'] == 'error':
                logger.debug(message['stack'])
