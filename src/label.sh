#!/bin/sh

## DEMO HACK - reset node:12 image
#docker images --format "{{.Repository}}:{{.Tag}}" | grep -q node:12
#if [ $? -eq 0 ]
#then
#	docker tag 7a73e56f893c node:12
#fi

img=$1
label=$2

if [ -z "$img" ]
then
	echo "Syntax: label.sh <image:tag> [label]" >&2
	exit 1
fi

if [ -z "$label" ]
then
	label="cipolice=approved"
fi

#lines=`docker images $img | wc -l`
docker inspect $img >/dev/null 2>&1
if [ $? -gt 0 ]
then
	echo "Error: image $img not found." >&2
	exit 1
fi

echo "Labels on $img before labelling:"
docker inspect -f "{{json .Config.Labels }}" $img

echo "FROM $img" | docker build --quiet --label $label -t $img -

echo "Labels on $img after labelling:"
docker inspect -f "{{json .Config.Labels }}" $img
