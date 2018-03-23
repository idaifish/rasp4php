from subprocess import check_output, CalledProcessError


class FPM(object):
    """Wrapper for FPM
    """
    def __init__(self):
        super().__init__()
        self.version = self.get_version()

    def is_running(self):
        try:
            check_output("pgrep -a php-fpm", shell=True)
            return True
        except CalledProcessError as e:
            return False

    def get_version(self):
        """return version of php-fpm
        """
        try:
            output = check_output("/usr/sbin/php-fpm* -v", shell=True).decode()
            return 'v' + output.split("\n")[0][:5][-1]     # '5' / '7'
        except CalledProcessError as e:
            return ''

    def get_master(self):
        try:
            check_output("pgrep -V", shell=True)
            output = check_output("pgrep -a php-fpm", shell=True).decode()
            return int(output.split()[0])
        except CalledProcessError as e:
            return None

    def get_current_workers(self):
        try:
            check_output("pgrep -V", shell=True)
            output = check_output("pgrep php-fpm", shell=True).decode()
            return list(map(int, output.split()[1:]))
        except CalledProcessError as e:
            return None


fpm = FPM()