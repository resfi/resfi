#!/bin/bash

sudo killall -9 check_mailbox_failure.sh
sleep 1
/home/robat/resfi/check_mailbox_failure.sh &

cd framework/
sudo python resfi_loader.py

