#!/bin/sh

opts="$@"
if [ -z $1 ]
then
	opts="-wr clair.rules"
fi
echo "CIPolicE launch options: $opts"

fname=`readlink -f $0`
cd `dirname $fname`
python3 -u cipolice.py $opts
