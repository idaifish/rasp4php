# RASP4PHP   ![license](https://img.shields.io/github/license/idaifish/rasp4php.svg) [![Build Status](https://travis-ci.com/idaifish/rasp4php.svg?branch=master)](https://travis-ci.com/idaifish/rasp4php)

Runtime Application Self-Protection for PHP, based on [Frida](https://www.frida.re), mostly used as a sensor for SIEM.


## Compatibility

Tested on Ubuntu 1604, PHP 5.x and 7.x are officially supported.


## Usage

**VM**

```bash
# pip install pipenv
$ pipenv install
$ pipenv shell

# Console
$ sudo pipenv run rasp-debug

# GELF UDP Output
$ sudo pipenv run rasp --graylog 127.0.0.1 --graylog-port 27017

# Webhook
$ sudo pipenv run rasp --webhook http://127.0.0.1:8080/webhooks
```

**Docker**

```bash
$ export RASP4PHP7_OPTION="--webhook http://127.0.0.1:8080/webhooks"
$ export RASP4PHP5_OPTION="--graylog 127.0.0.1 --graylog-port 27017"
$ docker-compose up
```
