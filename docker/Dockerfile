FROM debian:stretch
LABEL maintainer="Kyan Developers <dev@kyan.org>"
LABEL description="Dockerised KyanCore, built from Travis"

RUN apt-get update && apt-get -y upgrade && apt-get clean && rm -fr /var/cache/apt/*

COPY bin/* /usr/bin/
