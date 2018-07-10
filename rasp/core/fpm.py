from __future__ import unicode_literals
from subprocess import check_output, CalledProcessError

from builtins import super, object


class FPM(object):
    """A wrapper for PHP-FPM process."""

    def __init__(self):
        super().__init__()
        self.version = self.get_version()
        self.full_version = self.get_full_version()

    def is_running(self):
        try:
            check_output("pgrep -a php-fpm", shell=True)
            return True
        except CalledProcessError as e:
            return False

    def get_version(self):
        """return version of php-fpm."""

        try:
            self.process_name = check_output("ps -q `pgrep -u root php-fpm` -o comm=", shell=True).decode().strip('\n')
            return 'v' + self.process_name[7:8]     # '5' / '7'
        except CalledProcessError as e:
            return ''

    def get_full_version(self):
        """return version of php-fpm."""

        try:
            output = check_output("{} -v".format(self.process_name), shell=True).decode()
            return output.split("\n")[0][4:10]
        except CalledProcessError as e:
            return ''

    def get_modules(self):
        """return php modules."""

        try:
            cmd = "/usr/sbin/{} -m".format(self.process_name)
            output = check_output(cmd, shell=True).decode()
            output = output.split('\n\n')[0].split('\n')
            return list(filter(lambda x: x != '' and not x.startswith('['), output))
        except CalledProcessError as e:
            return []

    def get_disabled_functions(self):
        """return disabled functions."""

        try:
            cmd = "/usr/sbin/{} -i | grep disable_function".format(self.process_name)
            output = check_output(cmd, shell=True).decode()
            output = output.split('=>')[1].strip().split(',')
            if 'no value' in output:
                return []
            return list([i for i in output if i != ''])
        except CalledProcessError as e:
            return []

    def get_master(self):
        try:
            output = check_output("pgrep -a php-fpm", shell=True).decode()
            return int(output.split()[0])
        except CalledProcessError as e:
            return None

    def get_current_workers(self):
        try:
            output = check_output("pgrep php-fpm", shell=True).decode()
            return list(map(int, output.split()[1:]))
        except CalledProcessError as e:
            return None


# Singleton
fpm = FPM()
