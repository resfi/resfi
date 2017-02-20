"""
    The ResFi Configuration File

    Copyright (C) 2016 Sven Zehl, Anatolij Zubow, Michael Doering, Adam Wolisz

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    {zehl, zubow, wolisz, doering}@tkn.tu-berlin.de
"""

__author__ = 'zehl, zubow, wolisz, doering'



# RESFI CONFIG PARAMETERS
CONNECTOR = "linux"
DEBUG = True
LOGGING_PATH = "/tmp/"
# polling interval used by forwarding engine
SLEEP_DUR = 0.01 # Sleep duration of Forwarder loop
KEYCHANGEINTERVAL = 3600 # seconds min 10
CHANNEL_SWITCH_GUARD = 2 # to protect channel switch

# GENERAL CONFIG
WIRED_INTERFACE = "eth0" # backhauling interface
WIRELESS_INTERFACE = "ap5" # 802.11 wireless interface

FWD_PORT = "5559"
SND_PORT = "5560"
PROBE_REQ_PORT = "3333"

# LINUX CONNECTOR CONFIG
HOSTAPD_PATH = '../hostapd-20131120/hostapd/'
HOSTAPD_CTRL_PATH = '/tmp/hostapd-phy1/'

#Mininet CONNECTOR CONFIG
SCAN_SIMU_PORT = 50000
