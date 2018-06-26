from setuptools import setup, find_packages
from rasp.common.version import __VERSION__


setup(
    name='rasp4php',
    version=__VERSION__,
    keywords=('rasp', 'php', 'rasp4php', 'siem'),
    description='Runtime Application Self-Protection for PHP',
    url='https://github.com/idaifish/rasp4php',
    python_requires='>=3',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'frida',
        'coloredlogs',
        'graypy',
        'redis',
    ],
    scripts=('rasp-cli', ),
    author='idaifish',
    author_email='idaifish@gmail.com',
    license='MIT',
    classifiers=[
        'Topic :: Security',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Operating System :: POSIX :: Linux',
    ]
)
