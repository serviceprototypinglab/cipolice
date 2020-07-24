# Build instructions: docker build -t scanmeta .

FROM python:3-slim

LABEL maintainer="spio@zhaw.ch"

RUN pip3 install requests pika
RUN apt-get update && apt-get --assume-yes install --no-install-recommends docker.io && apt-get clean

COPY scan-meta.py /opt/

CMD ["/bin/sh", "-c", "cd /opt && python3 scan-meta.py"]
