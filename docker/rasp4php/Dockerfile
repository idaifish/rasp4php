FROM python:stretch

ENV SHELL /bin/bash

RUN pip install pipenv
RUN git clone --depth 1 git://github.com/idaifish/rasp4php.git /root/rasp4php
WORKDIR /root/rasp4php
RUN pipenv install --system

RUN apt update
RUN apt install -y php7.0-fpm
RUN mkdir /run/php

COPY www.conf /etc/php/7.0/fpm/pool.d/www.conf

ENTRYPOINT php-fpm7.0 -D && python rasp4php/main.py --debug