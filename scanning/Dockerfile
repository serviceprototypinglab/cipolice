FROM python:3.9-slim-buster

# install trivy - https://aquasecurity.github.io/trivy/v0.19.0/advanced/container/embed-in-dockerfile/
COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt find.py receiver.py scan.py ./

RUN pip install --no-cache-dir -r requirements.txt

CMD [ "/bin/bash", "-c", "python ./scan.py experiment"]