#!/bin/bash

if [ $# -eq 0 ]
  then
    echo "No arguments supplied; usage: $0 <PHYNAME>"
    exit 0
fi

PHYNAME=$1
echo "->Creating monitor interface mon0 for passive frame sniffing..."


sudo killall -9 hostapd
sleep 1
# cleanup
sudo iw dev mon0 del 2>/dev/null
sudo iw dev ap0 del 2>/dev/null
sleep 1

sudo iw phy $PHYNAME interface add wlan4 type managed

sleep 1

sudo ifconfig wlan4 up

sleep 1

sudo airmon-ng start wlan4

sleep 1

sudo iw dev wlan4 del

sleep 1

sudo iw dev mon0 set channel 120

sleep 1

sudo iw phy  $PHYNAME interface add ap0 type managed

sleep 1

sudo ifconfig ap0 up
#sudo iwconfig mon0 channel 44

sleep 1

sudo hostapd /home/robat/resfi/test/hostapd.conf &

sleep 1

sudo python /home/robat/resfi/test/simulate_stas2.py

sleep 1

sudo killall -9 hostapd
sudo iw dev ap0 del
sudo iw dev mon0 del 
