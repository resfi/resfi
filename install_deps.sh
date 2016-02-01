#!/bin/bash

echo "Installing base packages ... "
sudo apt-get update
sudo apt-get install git gawk build-essential autoconf libtool pkg-config

echo "Installing python-pip, netifaces for mininet ... "
sudo apt-get install python-pip
sudo pip install netifaces

echo "Installing ZeroMQ"
sudo apt-get install libzmq3-dev
sudo apt-get install python-zmq

echo "Installing libnl-dev for hostapd and iw..."
sudo apt-get install libnl-dev