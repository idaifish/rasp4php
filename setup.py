from setuptools import setup, find_packages
from rasp4php.__version__ import __VERSION__


setup(
    name = 'rasp4php',
    version = __VERSION__,
    keywords = ('rasp', 'php', 'rasp4php', 'siem'),
    description = 'Runtime Application Self-Protection for PHP',
    url = 'https://github.com/idaifish/rasp4php',
    python_requires='>=3',
    packages = find_packages(),
    install_requires = [
        'frida',
        'coloredlogs',
        'graypy',
        'redis',
    ],
    entry_points = """
        [console_scripts]
        rasp=rasp4php.main:main
    """,
    author = 'idaifish',
    author_email = 'idaifish@gmail.com',
    license='MIT',
)