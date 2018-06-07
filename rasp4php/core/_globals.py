from queue import Queue
from threading import Event


# Global MQ
message_queue = Queue()


# Detach Event
detach_event = Event()


# Runtime Environment
environment = {}