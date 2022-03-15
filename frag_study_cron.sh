#!/bin/bash

# arguments
## location to output results
OUTPUTDIR=$1
## location of bpf scripts
BPFDIR=$2

# check that we are running as root... otherwise a bunch of the following steps
# will fail...
if [ "$EUID" -ne 0 ] ; then
  echo "Please run as root"
  exit 1
fi

# randomly pick a minute during the next half hour to perform our sample
RANDMINUTE=$(( $RANDOM % 30 ))
RANDTIME=$( date +"%m-%d-%Y-%H-%M-%S" -d "$RANDMINUTE mins" )

# create the output directory
SAMPLEDIR="$OUTPUTDIR/$HOSTNAME-$RANDTIME/"
mkdir -p $SAMPLEDIR

# redirect output to a log
exec 3>&1 4>&2 >"$SAMPLEDIR/$RANDTIME.log" 2>&1

# sleep until that minute
date
echo "Sleeping for $RANDMINUTE minutes until about $RANDTIME..."
sleep "${RANDMINUTE}m"
echo "Waking up again... <yawn>"
date

# sample /proc/kpageflags
echo "Recording page flags"
cp /proc/kpageflags "$SAMPLEDIR/$RANDTIME.kpageflags"
echo "Compressing page flags sample"
gzip "$SAMPLEDIR/$RANDTIME.kpageflags"

date

# sample process table
echo "Recording process table"
ps -o rss=,vsz=,cputime=,etime=,comm= ax  | sort -n -k 1 -r > "$SAMPLEDIR/$RANDTIME.procs"

date

# collect a 1-minute long sample of (de)allocations
echo "Recording BPF allocations"
(uname -a | grep -q Ubuntu) || source scl_source enable devtoolset-7 llvm-toolset-7
$BPFDIR/trace_allocs.py 1 > "$SAMPLEDIR/$RANDTIME.allocs"

date
