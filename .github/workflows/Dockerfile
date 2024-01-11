From  kalilinux/kali-rolling

RUN apt-get update -y && apt-get install -y git python3 python3-pip debhelper dh-virtualenv 

WORKDIR /root/
COPY quark-engine /root/quark-engine

WORKDIR /root/quark-engine
RUN touch Makefile

CMD ["dpkg-buildpackage", "-us", "-uc", "-b"]
