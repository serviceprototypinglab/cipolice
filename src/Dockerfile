FROM python:3-slim

RUN pip3 install rule-engine flask

COPY *.rules cipolice.py xrules.py containeractions.py /opt/

EXPOSE 10080

CMD ["/bin/sh", "-c", "cd /opt && python3 cipolice.py -wr clair.rules"]
