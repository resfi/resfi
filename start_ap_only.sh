#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied; usage: $0 <phy>"
    exit 0
fi

phy=$1

# cleanup
for i in `seq 0 10`;
do
  sudo iw dev mon${i} del 2>/dev/null
  sudo iw dev wlan${i} del 2>/dev/null
  sudo iw dev wifi${i} del 2>/dev/null
  sudo iw dev ap${i} del 2>/dev/null
done

sudo rfkill unblock all 2>/dev/null

#Configuring AP
sleep 1
sudo killall -9 hostapd 2> /dev/null
sleep 1
sudo iw phy ${phy} interface add ap5 type monitor
sleep 1
sudo ifconfig ap5 192.168.6.1 netmask 255.255.255.0
sleep 1
sudo service network-manager stop /dev/null
sleep 1
sudo ./hostapd-20131120/hostapd/hostapd hostapd-20131120/hostapd/hostapd-ch40.conf &
