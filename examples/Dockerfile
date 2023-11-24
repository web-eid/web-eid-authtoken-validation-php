FROM php:fpm

COPY . /var/www/html

RUN apt-get update
RUN apt-get install unzip

COPY --from=composer /usr/bin/composer /usr/bin/composer
RUN composer install
