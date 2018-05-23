FROM python:stretch

RUN mkdir /code
WORKDIR /code
COPY . /code

RUN pip install pipenv
RUN pipenv install --system

RUN apt update
RUN apt-get install -y apt-transport-https curl
RUN curl https://packages.sury.org/php/apt.gpg | apt-key add -
RUN echo "deb https://packages.sury.org/php/ stretch main" | tee /etc/apt/sources.list.d/php5.list
RUN apt-get update

RUN apt-get install -y php5.6-fpm php7.0-fpm
RUN mkdir /run/php
RUN cp /code/docker/rasp4php/www.conf /etc/php/7.0/fpm/pool.d/www.conf
RUN cp /code/docker/rasp4php/www5.conf /etc/php/5.6/fpm/pool.d/www.conf