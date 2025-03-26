From  kalilinux/kali-rolling:latest

RUN apt-get update -y && apt-get install --no-install-recommends -y \
    git python3 python3-pip debhelper cmake gcc-13 g++-13\
    dh-virtualenv build-essential devscripts equivs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV CC=gcc-13 CXX=g++-13

COPY ping /usr/bin/ping
RUN chmod +x /usr/bin/ping

WORKDIR /root/
COPY quark-engine /root/quark-engine

WORKDIR /root/quark-engine
RUN touch Makefile

CMD ["dpkg-buildpackage", "-us", "-uc", "-b"]
