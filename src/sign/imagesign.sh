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

gpg --list-keys CIPolicE >/dev/null
if [ $? -ne 0 ]
then
	gpg --batch --gen-key imagesign-script
fi

docker inspect $img | jq ".[0].RootFS" > /tmp/rootfs

rm -f /tmp/rootfs.asc
gpg --detach-sign --armor --default-key CIPolicE /tmp/rootfs

../label.sh $img sig=`cat /tmp/rootfs.asc | tr '\n' ';' | tr ' ' '_'`
