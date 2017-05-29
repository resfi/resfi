#!/bin/bash

sleep 2

while true; do 
    if grep -F "mailbox.cpp" /tmp/resfi_console_demo.log
    then
        # code if found
        echo "Error found rebooting ResFi"
        sudo kill -9 $(ps aux | grep "sudo python resfi_loader.py" | awk '{ print $2 }' | head -n1)
        sudo kill -9 $(ps aux | grep "python resfi_loader.py" | awk '{ print $2 }' | head -n1)
        rm /tmp/resfi_console_demo.log
        sleep 1
        /home/robat/resfi/start_resfi_only.sh &> /tmp/resfi_console_demo.log &
        /home/robat/resfi/control_mailbox_failure.sh &
    else
        echo "Check complete, no erros found."
        # code if not found
    fi
    sleep 1
done
