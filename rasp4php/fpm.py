from subprocess import check_output, CalledProcessError

from log import logger


# PHP-FPM(default):
#   42784 php-fpm: master process (/etc/php/7.0/fpm/php-fpm.conf)
#   42789 php-fpm: pool www
#   42790 php-fpm: pool www
#
#   if pm = static:
#       hook worker process
#   else:
#       # pm = dynamic
#       hook worker process
#       hook master fork
#
def is_alive():
    logger.debug("Checking whether the php-fpm is running . . .")
    try:
        check_output("pgrep -a php-fpm", shell=True)
        logger.debug("OK, php-fpm is running")
        return True
    except CalledProcessError as e:
        return False


def get_version():
    """return version of php-fpm
    """
    try:
        output = check_output("/usr/sbin/php-fpm* -v", shell=True).decode()
        return 'v' + output.split("\n")[0][:5][-1]     # '5' / '7'
    except CalledProcessError as e:
        return ''


def get_master():
    try:
        check_output("pgrep -V", shell=True)
        output = check_output("pgrep -a php-fpm", shell=True).decode()
        return int(output.split()[0])
    except CalledProcessError as e:
        return None


def get_current_workers():
    try:
        check_output("pgrep -V", shell=True)
        output = check_output("pgrep php-fpm", shell=True).decode()
        return list(map(int, output.split()[1:]))
    except CalledProcessError as e:
        return None
