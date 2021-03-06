from __future__ import unicode_literals
from threading import Thread, Lock
from json import dumps

import frida
from builtins import super

from rasp.core.message import message_queue
from rasp.core.log import logger
from rasp.core.filter import FilterManager
from rasp.core.hooks import HooksManager


# Local device lock
attach_lock = Lock()


class HookMasterThread(Thread):
    """Hook PHP-FPM master."""

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

    def baseline_check(self, message, data):
        result = message['payload']
        baseline = {
            'allow_url_include': '',
            'allow_url_fopen': '1',
            'auto_prepend_file': '',
            'auto_append_file': '',
            'expose_php': '',
            'display_errors': '',
            'open_basedir': '',
            'short_open_tag': '',
            'yaml.decode_php': None,
        }

        for ini_key, ini_value in baseline.items():
            if result[ini_key] != ini_value:
                logger.info("[Sensitive INI] {} => {}".format(ini_key, bool(result[ini_key])))

    def run(self):
        # pm = dynamic
        self.session.enable_child_gating()

        # Baseline check.
        baseline_script = self.session.create_script(HooksManager().get_baseline_script())
        baseline_script.on('message', self.baseline_check)
        baseline_script.load()

        self.detach_event.wait()
        self.session.detach()


class HookWorkerThread(Thread):
    """Hook PHP-FPM workers."""

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
        for hook in self.hooks:
            logger.debug("Setting up hook '{}' for Worker-{}".format(hook.name, self.worker_pid))

            feedback = """
            send("HookWorkerThread-{worker_pid}: Function {func_name} is hooked successfully");
            """.format(worker_pid=self.worker_pid, func_name=hook.name)
            script = self.session.create_script(hook.script + feedback)
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
    """Messages handler."""

    def __init__(self):
        super().__init__()
        self.message_queue = message_queue
        self.name = "NotificationThread"
        self.filter_manager = FilterManager()

    def run(self):
        logger.info("Notification Thread is starting.")

        while True:
            message = self.message_queue.get()

            if message['type'] == 'send':
                if not isinstance(message['payload'], dict):
                    logger.debug(message['payload'])
                else:
                    if self.filter_manager.filter(message['payload']):
                        logger.critical(dumps(message['payload']))
            elif message['type'] == 'error':
                logger.debug(message['stack'])
            elif message['type'] == 'exit':
                logger.info("Byebye~")
                break
