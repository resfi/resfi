#!/bin/bash
me="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"

if [ $# -eq 0 ]
  then
    echo -e echo "Unknown command in argument.\nPossible Commands:\n\t\t $me start \n\t\t $me stop \n\t\t $me del_logs"
    exit 0
fi

if [ "$1" == "start" ]
then
    echo "**********************************"
    echo "*********** ResFi DEMO ***********"
    echo "**********************************"
    sleep 1
	#1st start hostapds
	echo "-> starting Home Wi-Fi Networks in Worst Case Scenario"
    echo "-> starting hostapd on Home AP 1"
	ssh 192.168.200.29 "sudo killall hostapd &2>mute.log"
	ssh -f 192.168.200.29 "cd /home/robat/resfi/ && /home/robat/resfi/start_ap_only.sh phy0 &> /tmp/hostapd_home1.log"
	
	echo "-> starting hostapd on Home AP 2"
	ssh 192.168.200.10 "sudo killall -9 hostapd &2>mute.log"
	ssh -f 192.168.200.10 "cd /home/robat/resfi/ && /home/robat/resfi/start_ap_only.sh phy0 &> /tmp/hostapd_home2.log"
    
    echo "-> starting hostapd on Home AP 3"
	ssh 192.168.200.40 "sudo killall -9 hostapd &2>mute.log"
	ssh -f 192.168.200.40 "cd /home/robat/resfi/ && /home/robat/resfi/start_ap_only.sh phy0 &> /tmp/hostapd_home3.log"
    
    echo "-> starting hostapd on Home AP 4"
	ssh 192.168.200.15 "sudo killall -9 hostapd &2>mute.log"
	ssh -f 192.168.200.15 "cd /home/robat/resfi/ && /home/robat/resfi/start_ap_only.sh phy0 &> /tmp/hostapd_home4.log"

    #sleep 30
    echo "Home APs started, 30s to wait until AP Cooperation and ResFi Channel Assignment Application will be started"
    sleep 30
    
    echo "-> starting ResFi on Home APs...."
    echo "-> starting ResFi on Home AP 1"
#	ssh 192.168.200.29 "sudo killall -9 python &2>mute.log"
	ssh -f 192.168.200.29 "cd /home/robat/resfi/ && /home/robat/resfi/start_resfi_only.sh &> /tmp/resfi_console_home1.log"
	sleep 20
	
	echo "-> starting ResFi on Home AP 2"
#	ssh 192.168.200.10 "sudo killall -9 python &2>mute.log"
	ssh -f 192.168.200.10 "cd /home/robat/resfi/ && /home/robat/resfi/start_resfi_only.sh &> /tmp/resfi_console_home2.log"
    sleep 30
    
    echo "-> starting ResFi on Home AP 3"
#	ssh 192.168.200.40 "sudo killall -9 python &2>mute.log"
	ssh -f 192.168.200.40 "cd /home/robat/resfi/ && /home/robat/resfi/start_resfi_only.sh &> /tmp/resfi_console_home3.log"
    sleep 30
    
    echo "-> starting ResFi on Home AP 4"
#	ssh 192.168.200.15 "sudo killall -9 python &2>mute.log"
	ssh -f 192.168.200.15 "cd /home/robat/resfi/ && /home/robat/resfi/start_resfi_only.sh &> /tmp/resfi_console_home4.log"
    
    echo  "ResFi with Channel Assignment Application on all Home APs started"

    sleep 60000
    #echo "Starting Interfering Wi-Fi Network"
    #sudo /home/robat/resfi/test/start_nrf_ap.sh phy1
    #sleep 1
    #echo "Interferer turned off, waiting till ResFi APs found good assignment again"
    #sleep 60
    #echo "Repeating Demo, stopping everything."
    /home/robat/resfi/demo.sh stop
    sleep 1
    /home/robat/resfi/demo.sh start    
	
elif [ $1 = "stop" ]
then
	ssh 192.168.200.29 "sudo killall -9 hostapd"
	ssh 192.168.200.29 "sudo ifconfig ap5 down"
        ssh 192.168.200.29 "sudo killall -9 python"
        ssh 192.168.200.29 "rm /tmp/resfi_console_home1.log"
        ssh 192.168.200.10 "sudo killall -9 hostapd"
        ssh 192.168.200.10 "sudo ifconfig ap5 down"
        ssh 192.168.200.10 "sudo killall -9 python"
        ssh 192.168.200.10 "rm /tmp/resfi_console_home2.log"
        ssh 192.168.200.40 "sudo killall -9 hostapd"
        ssh 192.168.200.40 "sudo ifconfig ap5 down"
        ssh 192.168.200.40 "sudo killall -9 python"
        ssh 192.168.200.40 "rm /tmp/resfi_console_home3.log"
        ssh 192.168.200.15 "sudo killall -9 hostapd"
        ssh 192.168.200.15 "sudo ifconfig ap5 down"
        ssh 192.168.200.15 "sudo killall -9 python"
        ssh 192.168.200.15 "rm /tmp/resfi_console_home4.log"

else
	echo "Unknown command in argument.\nPossible Commands:\n\t\t $me start \n\t\t $me stop \n\t\t $me del_logs"
fi

