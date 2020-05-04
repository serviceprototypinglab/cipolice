# Image Scanner

Wraps around `docker pull` and scans an image with Clair. Will print the image
tag and the highest CVE severity level found in the image.

## Prerequisites

- Install Docker and docker-compose
- Install Klar, erlang and RabbitMQ server with `scanner_setup.sh`
- `pip install -r requirements.txt`

## Setup

Run clair:
```
cd clair-test
sudo docker-compose up -d
```
Keep in mind that clair takes a while to populate the CVE database the first time,
and during that time it will return no vulnerabilities. This takes 20-30 minutes.

## Usage

The program has two modes, 'experiment' and 'pull'.

### Pull mode

Pull mode will pull the image to the local registry and scan it with clair.
It will print the 'message' that will be sent to the policy engine.

Example:
```
$ python3 scan.py pull nginx:latest

...

Image: nginx:latest, Result: Low
```
The severity levels for clair are:
- Unknown
- Negligible
- Low
- Medium
- High
- Critical
- Defcon1

Refer to clair's documentation for a detailed explanation of the severity levels.
The program will return 'None' if no vlunerabilities are found by clair.

### Experiment mode

Experiment mode will scan all images of the official `library` registry to
obtain an overview of the security status of official images.

Be aware that this
mode will use a large amount of storage and despite cleaning up, some data will
remain. As of now, it can consume ~80 GB.

 Here are some sample results, limited to 'Low' vulnerabilities or higher.

- Total images: 160
- Images scanned successfully: 148
- At least one Low: 108 (73%)
- At least one Medium: 39 (26%)
- At least one High: 6 (4%)
