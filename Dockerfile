# syntax=docker/dockerfile:1

FROM python:3.12-alpine3.19

ENV PYCURL_SSL_LIBRARY=openssl

# Install dependencies
RUN apk add --no-cache ffmpeg libcurl

WORKDIR /app

RUN apk add --no-cache --virtual .build-dependencies build-base curl-dev \
    && pip install pycurl \
    && apk del .build-dependencies

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY *.py ./
COPY streamonitor ./streamonitor

RUN addgroup -g 1000 appuser && \
    adduser -u 1000 -G appuser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 5000
CMD [ "python3", "Downloader.py"]

