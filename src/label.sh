#!/bin/sh

img=$1

if [ -z "$img" ]
then
	echo "Syntax: label.sh <image:tag>" >&2
	exit 1
fi

echo "Labels on $img before labelling:"
docker inspect -f "{{json .Config.Labels }}" $img

echo "FROM $img" | docker build --quiet --label cipolice="approved" -t $img -

echo "Labels on $img after labelling:"
docker inspect -f "{{json .Config.Labels }}" $img
