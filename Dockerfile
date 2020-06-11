FROM python:3.7-slim AS build-env

COPY . /app
WORKDIR /app
RUN pip install pipenv && \
  pipenv install --skip-lock

WORKDIR /app/quark
ENTRYPOINT ["pipenv", "run"]
