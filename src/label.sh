#!/bin/sh

img=node:12

echo "Labels on $img before labelling:"
docker inspect -f "{{json .Config.Labels }}" $img

echo "FROM $img" | docker build --quiet --label cipolice="approved" -t $img -

echo "Labels on $img after labelling:"
docker inspect -f "{{json .Config.Labels }}" $img
