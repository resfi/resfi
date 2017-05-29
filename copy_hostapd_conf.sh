#!/bin/bash

if [ "$HOSTNAME" = "resfi-demo1" ]; then
    cp /home/robat/resfi/hostapd-20131120/hostapd/hostapd-demo1.conf /home/robat/resfi/hostapd-20131120/hostapd/hostapd-ch40.conf
elif [ "$HOSTNAME" = "resfi-demo2" ]; then
    cp /home/robat/resfi/hostapd-20131120/hostapd/hostapd-demo2.conf /home/robat/resfi/hostapd-20131120/hostapd/hostapd-ch40.conf
elif [ "$HOSTNAME" = "resfi-demo3" ]; then
    cp /home/robat/resfi/hostapd-20131120/hostapd/hostapd-demo3.conf /home/robat/resfi/hostapd-20131120/hostapd/hostapd-ch40.conf
elif [ "$HOSTNAME" = "resfi-demo4" ]; then
    cp /home/robat/resfi/hostapd-20131120/hostapd/hostapd-demo4.conf /home/robat/resfi/hostapd-20131120/hostapd/hostapd-ch40.conf
else
    echo "WARNING: no appropriate hostapd config found for node, using standard config"
fi
