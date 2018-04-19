# RASP4PHP

Runtime Application Self-Protection for PHP, based on [Frida](https://www.frida.re), mostly used as a sensor for SIEM.


## Usage

```bash
$ pipenv install
$ pipenv shell
$ sudo pipenv run rasp4php
$ sudo pipenv run debug-rasp4php      # Debug
```

## Graylog Support

```
# GELF UDP
GRAYLOG_HOST = '127.0.0.1'
GRAYLOG_PORT = 12201
```

## Restriction

PHP-FPM's process manager must be "static".