#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied; usage: $0 <PHYNAME>"
    exit 0
fi

PHYNAME=$1
echo "->Creating monitor interface mon0 for passive frame sniffing..."

# cleanup
sudo iw dev mon0 del 2>/dev/null

sleep 1

sudo iw phy $PHYNAME interface add mon0 type managed

sleep 1

sudo ifconfig mon0 up

sleep 1

sudo dumpcap -i mon0 -I -c 1

#sleep 1

#sudo iwconfig mon0 channel 44
