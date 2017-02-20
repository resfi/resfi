#!/bin/bash

echo "Installing base packages ... "
sudo apt-get update
sudo apt-get -y install git gawk build-essential autoconf libtool pkg-config

echo "Installing python-pip, netifaces for mininet ... "
sudo apt-get -y install python-dev
sudo apt-get -y install python-pip
sudo pip install netifaces
sudo pip install pycrypto

echo "Installing ZeroMQ"
sudo apt-get -y install libzmq3-dev
sudo apt-get -y install python-zmq

echo "Installing libnl-dev for hostapd and iw..."
sudo apt-get -y install libnl-3-dev
sudo apt-get -y install libnl-genl-3-dev

echo "##########################################"
echo "ResFi setup finished." 
echo "Please adjust CONNECTOR and WIRED_INTERFACE" 
echo "in file framework/config.py"
echo ""
echo "Start ResFi Agent with:" 
echo "./start_resfi.sh phyX"
echo "##########################################"
