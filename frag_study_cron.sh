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
SAMPLEDIR="$OUTPUTDIR/$HOSTNAME/$RANDTIME/"
mkdir -p $SAMPLEDIR

# redirect output to a log
exec 3>&1 4>&2 >"$SAMPLEDIR/log" 2>&1

# sleep until that minute
date
echo "Sleeping for $RANDMINUTE minutes until about $RANDTIME..."
sleep "${RANDMINUTE}m"
echo "Waking up again... <yawn>"
date

# sample /proc/kpageflags
echo "Recording and compressing page flags"
cat /proc/kpageflags | gzip > "$SAMPLEDIR/kpageflags.gz"

date

# sample process table
echo "Recording process table"
ps -o rss=,vsz=,cputime=,etime=,comm= ax  | sort -n -k 1 -r > "$SAMPLEDIR/procs"

# collect some system info
echo "Record kernel version and hostname"
hostname > "$SAMPLEDIR/info"
uname -a >> "$SAMPLEDIR/info"
/usr/sbin/dmidecode >> "$SAMPLEDIR/info"

# collect info about overall memory usage
echo "Record /proc/meminfo"
cat /proc/meminfo > "$SAMPLEDIR/meminfo"

date

# collect info about uptime
echo "Record uptime"
uptime > "$SAMPLEDIR/uptime"

date

# collect and compress a 1-minute long sample of (de)allocations
echo "Recording BPF allocations"
$BPFDIR/trace_allocs.py 1 | gzip > "$SAMPLEDIR/allocs.gz"

date

# chown files if on condor.
echo "Changing owner from root..."
if [[ `hostname` = *"chtc.wisc.edu" ]] ; then
  chown -R mmansi "$OUTPUTDIR/$HOSTNAME/"
fi
