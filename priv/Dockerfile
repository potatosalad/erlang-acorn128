FROM ubuntu:eoan

ARG DEBIAN_FRONTEND=noninteractive

ARG OTP_VERSION=local
ENV OTP_VERSION ${OTP_VERSION}

RUN apt-get update && \
    apt-get -y install curl gnupg2 && \
    curl -O https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb && \
    dpkg -i erlang-solutions_1.0_all.deb && \
    apt-get update && \
    apt-get -y install esl-erlang=1:${OTP_VERSION}-1 git make clang-9

ENV CC clang-9
ENV CXX clang++-9

RUN mkdir /build
WORKDIR /build
