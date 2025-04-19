FROM debian:trixie

COPY . /app
WORKDIR /app

COPY ping /usr/bin/ping
RUN chmod +x /usr/bin/ping

RUN apt-get update \
    && apt-get install --no-install-recommends -y git=1:2.47.2-0.1 \
    graphviz=2.42.4-3 cmake=3.31.6-1 \
    build-essential=12.12 gcc-13=13.3.0-13 \
    g++-13=13.3.0-13 ca-certificates=20241223 \
    zlib1g-dev=1:1.3.dfsg+really1.3.1-1+b1 \
    libgdbm-dev=1.24-2 libnss3-dev=2:3.109-1 \
    libssl-dev=3.4.1-1 libreadline-dev=8.2-6 \
    libffi-dev=3.4.7-1 libsqlite3-dev=3.46.1-2 \
    wget=1.25.0-2 libbz2-dev=1.0.8-6 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://www.python.org/ftp/python/3.10.0/Python-3.10.0.tgz \
    && tar -xvf Python-3.10.0.tgz

WORKDIR /app/Python-3.10.0
RUN ./configure \
    && make \
    && make altinstall

WORKDIR /app
RUN ln -s /usr/local/bin/python3.10 /usr/bin/python \
    && ln -s /usr/local/bin/pip3.10 /usr/bin/pip

ENV CC=gcc-13 CXX=g++-13
RUN pip install --upgrade pipenv==2024.4.1 pip==25.0.1 \
    && pipenv install --skip-lock
RUN pipenv run freshquark

WORKDIR /app/quark
ENTRYPOINT ["pipenv", "run"]
