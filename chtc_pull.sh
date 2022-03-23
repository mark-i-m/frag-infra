#!/bin/bash

if [ "$#" -ne 3 ] ; then
  echo "Usage: ./script USER HOST OUTPUT"
  exit -1
fi

USER=$1
HOST=$2
OUTPUT=$3

REMOTEPATH="/home/$USER/frag_study/"

# Exit on error...
set -e

# Convenience
function exec_remote {
  ssh "${USER}@${HOST}" -- $1
}

SAMPLES=$(exec_remote 'ls '$REMOTEPATH'/`hostname`/')

REMOTEHOSTNAME=$(exec_remote hostname)

mkdir -p "$OUTPUT/$REMOTEHOSTNAME/"

for path in $SAMPLES ; do
  echo "==================================================="
  echo "Copying: $path"

  # copy file
  rsync -avzP "${USER}@${HOST}:${REMOTEPATH}/${REMOTEHOSTNAME}/${path}" "$OUTPUT/${REMOTEHOSTNAME}/"

  # check hashes to make sure no corruption
  REMOTEHASH=$(exec_remote 'sha256sum '"${REMOTEPATH}/${REMOTEHOSTNAME}/${path}/"'* | cut -d " " -f 1')
  LOCALHASH=$(sha256sum "$OUTPUT/${REMOTEHOSTNAME}/${path}/"* | cut -d " " -f 1)
  if [ ! "$REMOTEHASH" = "$LOCALHASH" ] ; then
    echo "Hash for files not equal"
    echo "${REMOTEHOSTNAME}/${path}"
    echo "Local" $LOCALHASH
    echo "Remote" $REMOTEHASH
    exit -1
  else
    echo "Hashes equal"
    echo "Local" $LOCALHASH
    echo "Remote" $REMOTEHASH
  fi

  # rm file on remote
  #exec_remote 'rm -r '"${REMOTEPATH}/${REMOTEHOSTNAME}/${path}"
done
