from platform import platform


class Runtime(object):
    environment = {} 

    def __init__(self):
        self.environment['platform'] = platform()


runtime = Runtime()
