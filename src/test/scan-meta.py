import requests
import json
import os
import subprocess
import time
import sys
try:
    import pika
except:
    print("(Warning: no message queue mode due to missing pika.)")

userid = "jszhaw" # username or 'library'
registryapi = "https://hub.docker.com/v2/" # docker hub or private registry

if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
    print("Syntax: scanmeta [<userid>] [<registryapi>]")
    print(f"Defaults: userid={userid}, registryapi={registryapi}")
    exit()

if len(sys.argv) >= 2:
    userid = sys.argv[1]
if len(sys.argv) >= 3:
    registryapi = sys.argv[2]

def printcol(s):
    colors = {
        "green":    "\u001b[32m",
        "yellow":   "\u001b[33m",
        "red":      "\u001b[31m",
        "blue":     "\u001b[34m",
        "reset":    "\u001b[0m"
    }
    print(colors["yellow"] + s + colors["reset"])

# Adapted from scan.py

def get_names(registryapi, userid):
    if registryapi.endswith("/"):
        registryapi = registryapi[:-1]
    link = f"{registryapi}/repositories/{userid}/"
    names = []
    while True:
        data = json.loads(requests.get(link).text)
        if data['next'] is None:
            break
        link = data['next']
        for item in data['results']:
            names.append(item['name'])
    return names

def get_labels(img):
    cmd = f"docker inspect -f \"{{{{json .Config.Labels}}}}\" {img}"
    print(cmd)
    p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    labels = p.stdout.decode().strip()
    if labels == "null":
        return {}
    return json.loads(labels)

def scan_images(registryapi, userid):
    if "pika" in globals():
        printcol("Setting up message queue...")
        wait = 1
        while True:
            try:
                # TODO setting to 0 is discouraged, but proper handling would require adaptive reconnection later
                connection = pika.BlockingConnection(pika.ConnectionParameters("localhost", heartbeat=0))
            except:
                print(f"- not yet ready; wait {wait}s...")
                time.sleep(wait)
                wait *= 1.5
                wait = int(wait * 10) / 10
            else:
                break
        channel = connection.channel()
        channel.queue_declare(queue="hello")

    printcol(f"Retrieving all images from user '{userid}' @ '{registryapi}'")
    images = get_names(registryapi, userid)
    for image in images:
        printcol(f"Check {image}...")
        fqimage = f"{userid}/{image}"
        os.system(f"docker pull {fqimage}")

        cmd = f"docker images {fqimage} --format '{{{{.Size}}}}'"
        print(cmd)
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        imgsize = p.stdout.decode().strip()

        if imgsize.endswith("GB"):
            imgsizemb = int(float(imgsize[:-2]) * 1024)
        elif imgsize.endswith("MB"):
            imgsizemb = int(imgsize[:-2])
        elif imgsize.endswith("kB"):
            imgsizemb = 1
        else:
            imgsizemb = 0

        labels = get_labels(f"{fqimage}")
        # Working around the fact that rule_engine only supports list, not dict
        msglabels = list(labels.keys())

        msg = {"image": fqimage, "size-mb": imgsizemb, "labels": msglabels}
        msg = json.dumps(msg)

        if "pika" in globals():
            printcol(f"Emit event {msg}...")
            channel.basic_publish(exchange="", routing_key="hello", body=msg)
        else:
            printcol(f"Not emitting {msg}.")

    if "pika" in globals():
        connection.close()

scan_images(registryapi, userid)
