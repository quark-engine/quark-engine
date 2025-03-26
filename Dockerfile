FROM debian:trixie

COPY . /app
WORKDIR /app

COPY ping /usr/bin/ping
RUN chmod +x /usr/bin/ping

RUN apt-get update \
    && apt-get install --no-install-recommends -y git graphviz cmake \
    build-essential gcc-13 g++-13 ca-certificates zlib1g-dev libncurses5-dev \
    libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev \
    libsqlite3-dev wget libbz2-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz \
    && tar -xvf Python-3.10.0.tgz \
    && cd Python-3.10.0 \
    && ./configure \
    && make \
    && make altinstall \
    && cd - \
    && ln -s /usr/local/bin/python3.10 /usr/bin/python \
    && ln -s /usr/local/bin/pip3.10 /usr/bin/pip

ENV CC=gcc-13 CXX=g++-13
RUN pip install --upgrade pipenv pip \
    && pipenv install --skip-lock
RUN pipenv run freshquark

WORKDIR /app/quark
ENTRYPOINT ["pipenv", "run"]
