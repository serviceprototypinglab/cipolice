# Build instructions: docker build -t cipolice .

FROM python:3-slim

LABEL maintainer="spio@zhaw.ch"

RUN pip3 install rule-engine flask pika
RUN apt-get update && apt-get --assume-yes install --no-install-recommends docker.io wget jq && apt-get clean

RUN wget -q https://mirror.openshift.com/pub/openshift-v4/clients/oc/latest/linux/oc.tar.gz && tar xf oc.tar.gz && rm oc.tar.gz && mv oc /usr/local/bin

COPY *.rules cipolice.py xrules.py containeractions.py label.sh /opt/

EXPOSE 10080

CMD ["/bin/sh", "-c", "cd /opt && python3 cipolice.py -wr clair.rules"]
