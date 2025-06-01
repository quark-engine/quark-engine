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
RUN shurikenCommit='b26778813b487aa55e7e183d153ec83300f4e075' && \
    shurikenSource="\"ShurikenAnalyzer @ git+https://github.com/Fare9/Shuriken-Analyzer.git@$shurikenCommit#subdirectory=shuriken/bindings/Python/\"," && \
    sed -i "s|required_requirements = \[|required_requirements = [\n    $shurikenSource|" setup.py

RUN touch Makefile

CMD ["dpkg-buildpackage", "-us", "-uc", "-b"]
