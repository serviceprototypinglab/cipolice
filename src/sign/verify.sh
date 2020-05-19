#!/bin/sh

img=$1

if [ -z "$img" ]
then
	echo "Syntax: imagesign.sh <image:tag>" >&2
	exit 1
fi

docker inspect $img >/dev/null 2>&1
if [ $? -gt 0 ]
then
	echo "Error: image $img not found." >&2
	exit 1
fi

sig=`docker inspect -f "{{json .Config.Labels }}" $img | jq .sig`
echo $sig | tr -d '"' | tr ';' '\n' | tr '_' ' ' > /tmp/verify.asc

docker inspect $img | jq ".[0].RootFS" > /tmp/rootfs

gpg --verify /tmp/verify.asc /tmp/rootfs

if [ $? -eq 0 ]
then
	echo valid
else
	echo invalid
fi

# ERROR:
# gpg: keine abgetrennte Signatur / gpg: not a detached signature
