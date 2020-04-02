# Image Scanner

Wraps around `docker pull` and scans an image with Clair. Will print the image
tag and return code of the scan. The scan succeeds when no vulnerability of
'high' severity or higher is found.

## Prerequisites

- Install Docker
- `pip install -r requirements.txt`

## Usage

Example for the `ubuntu:latest` image:
```
python scan.py ubuntu:latest
```
