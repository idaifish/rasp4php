FROM python:stretch

RUN mkdir /code
WORKDIR /code
COPY . /code

RUN pip install pipenv
RUN pipenv install --system

RUN apt update
RUN apt install -y php7.0-fpm
RUN mkdir /run/php
RUN cp /code/docker/rasp4php/www.conf /etc/php/7.0/fpm/pool.d/www.conf

ENTRYPOINT ["sh", "-c", "php-fpm7.0 -D ; python rasp4php/main.py"]
CMD ["--debug"]