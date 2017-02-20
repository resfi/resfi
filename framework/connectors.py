"""
    ResFi connector modules
    Base class of all connector modules. Currently ResFi supports two platforms:
    - Linux-based systems (Debian/Ubuntu)
    - Emulation in Mininet

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

import config
from config import HOSTAPD_PATH
from config import WIRED_INTERFACE
from config import HOSTAPD_CTRL_PATH
from utils import NetworkHelper
from utils import Neighbor
from utils import ParsingHelper
from common.resfi_api import ResFiSouthBoundAPI
from utils import WiFiHelper
from Crypto import Random
import netifaces as ni
import socket as sock
import array
import fcntl
import struct
import subprocess
import time
import netifaces as ni
import zmq


class AbstractConnector(ResFiSouthBoundAPI):
    def __init__(self, log):
        self.debug = config.DEBUG
        self.log = log
        self.wifi_helper = WiFiHelper(log)
        self.network_helper = NetworkHelper(log)
        self.parsing_helper = ParsingHelper(log)
        self.freq = 0
        self.channel = 0

    """
    Helper for execution of native commands
    """
    def run_command(self, command):
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        result = p.communicate()[0]
        return result

"""
    Connector module for the Linux platform implementing the ResFi southbound API.
    TODO:
    - sudo : do we really need it?
"""
class LinuxConnector(AbstractConnector):
    def __init__(self, log):
        AbstractConnector.__init__(self, log)
        self.hostap_path = HOSTAPD_PATH

    def getWiredInterface(self):
        return WIRED_INTERFACE

    def getHostname(self):
        ni.ifaddresses(WIRED_INTERFACE)
        hostname = ni.ifaddresses(WIRED_INTERFACE)[2][0]['addr']
        return hostname

    def getInterfaceList(self):
        return self.network_helper.all_interfaces()

    def getIPList(self):
        ips = []  # list of all ips
        for i in self.getInterfaceList():
            ips.append(self.network_helper.format_ip(i[1]))
        return ips

    def addIEtoProbeResponses(self, pubKeyStr, SymKeyStr, SymIVStr, IpStr):
        self.log.debug('Linux:: program IE in probe responses')
        self.log.debug("EncryptKey: %s " % str(SymKeyStr))
        self.log.debug("Encrypt IV: %s" % str(SymIVStr))
        self.log.debug("Pub KEY: %s" % str(pubKeyStr))
        self.log.debug("IP: %s" % str(IpStr))

        command = HOSTAPD_PATH + 'hostapd_cli -p ' + HOSTAPD_CTRL_PATH + ' add_ie b16b00 b5 ' \
                  + SymKeyStr + SymIVStr + pubKeyStr + IpStr
        ret = self.run_command(command)

        self.log.debug(ret)

    def performActiveScan(self, fullScan, ssid, freq, pubKeyStr, SymKeyStr, SymIVStr, IpStr, ownFreq):
        self.log.debug('Linux:: performActiveScan()')

        neighborList = {}
        if fullScan:
            payloadString = SymKeyStr + SymIVStr + pubKeyStr + IpStr
            dotFormattedIE = self.wifi_helper.hex_to_vendor_spec_ie(payloadString, True)
            dotFormattedIE2 = self.wifi_helper.hex_to_vendor_spec_ie(str(ownFreq), True)
            self.log.debug("Performing full WiFi scan, including big ResFi IE")
            command = 'sudo ../iw-4.3/iw dev ap5 scan -u ies ' + dotFormattedIE + ":" + dotFormattedIE2 + ' ap-force'
            self.log.debug(str(command))
        else:
            if len(ssid) == 0:
                command = 'sudo ../iw-4.3/iw dev ' + config.WIRELESS_INTERFACE + ' scan -u freq ' + str(
                    freq) + ' ap-force'
            else:
                command = 'sudo ../iw-4.3/iw dev ' + config.WIRELESS_INTERFACE + ' scan -u freq ' + str(
                    freq) + ' ap-force ssid ' + str(ssid)
        ret = self.run_command(command)

        dataArray = []
        for line in ret.splitlines():
            if "freq: " in line:
                freq = line.replace("freq: ", "")
                freq = freq.replace(" ", "")
                freq = freq.replace("\n", "")
            if "signal: " in line:
                rssi = line.replace("signal: ", "")
                rssi = rssi.replace(".00 dBm", "")
                rssi = rssi.replace("\n", "")
            if "SSID: " in line:
                ssid = line.replace("SSID: ", "")
                ssid = ssid.replace("\t", "")
                ssid = ssid.replace("\n", "")
            if "Vendor specific: OUI b1:6b:00, data: b5 " in line:
                line = line.replace("Vendor specific: OUI b1:6b:00, data: b5 ", "")
                entry = freq, ssid, rssi, line
                dataArray.append(entry)

        if len(dataArray) > 0:
            for i in range(0, len(dataArray)):
                entryTemp = dataArray[i]
                freqTemp = entryTemp[0]
                ssidTemp = entryTemp[1]
                rssiTemp = entryTemp[2]
                data = entryTemp[3]

                self.log.debug(data)

                if not isinstance(data, str):
                    continue
                elif len(data) <= 10:
                    continue
                data = data.replace(" ", "")
                data = data.replace("\n", "")
                data = data.replace("\t", "")

                self.log.debug(data)

                newNeighborEntry = self.parsing_helper.parse_resfi_ie(data, len(SymKeyStr), len(SymIVStr),
                                                                      len(pubKeyStr), 0, int(rssiTemp), int(freqTemp),
                                                                      ssidTemp)
                if newNeighborEntry.ipAddress == "Error":
                    continue

                neighborList[newNeighborEntry.ipAddress] = newNeighborEntry
        else:
            self.log.debug("No neighbor APs found...")

        return neighborList

    def getAPparams(self):
        command = HOSTAPD_PATH + 'hostapd_cli -p ' + HOSTAPD_CTRL_PATH + ' get_config | grep "=" | cut -f2- -d"="'
        ret = self.run_command(command)

        retParams = ret.split('\n')
        channel = int(retParams[0])
        self.channel = channel
        freq = self.wifi_helper.translateChannelToFrequency(channel)
        self.freq = freq
        bssid = retParams[1]
        ssid = retParams[2]
        params = {'channel': channel, 'bssid': bssid, 'ssid': ssid, 'freq': freq}
        return params
        # print "BSSID: "+str(self.bssid) + " SSID: "+str(self.ssid) + "  Channel: "+str(self.channel) + " Frequency: "+str(self.freq)


    # ResFiSouthBoundAPI
    def subscribeToProbeRequests(self, callback):
        ctx = zmq.Context()
        s = ctx.socket(zmq.SUB)
        s.connect("tcp://127.0.0.1:" + config.PROBE_REQ_PORT)
        s.setsockopt(zmq.SUBSCRIBE, '')

        while True:
            prPayload = s.recv()
            if "RSSI:" in prPayload:
                rssi = prPayload.split("RSSI:", 1)[1]
                prPayload = prPayload.split("RSSI:", 1)[0]
                # print "RSSI: "+ str(rssi)
            # print prPayload
            callback(prPayload, rssi)

    """
        Set radio channel of AP
    """
    def setChannel(self, freq):
        command = 'sudo ' + HOSTAPD_PATH + 'hostapd_cli -p ' + HOSTAPD_CTRL_PATH + ' chan_switch 5 ' + str(freq)
        ret = self.run_command(command)
        ret = ret.split('\n')[1]
        if ret == 'OK':
            self.freq = freq
            self.channel = self.wifi_helper.translateFrequencyToChannel(freq)
        return ret

    def getChannel(self):
        if self.channel == 0:
            self.getAPparams()
        return self.channel

    """
        Get physical interface
    """
    def getPhy(self):
        command = "iw " + config.WIRELESS_INTERFACE + " info | awk '$1 == \"wiphy\" {print $2}'"
        ret = self.run_command(command)
        ret = ret.split('\n')[0]
        return ret

    """
        Get available channels, i.e. those which are not disabled + require no passive scanning (DFS)
    """
    def getAvailableChannels(self, restrict5Ghz=False):
        phy = self.getPhy()
        self.log.debug('ResFi: phy <%s>' % str(phy))

        command = "sudo iw phy" + phy + " info | egrep -v 'disabled' | grep -v 'passive scanning' | grep MHz | awk '{ print $2 }' | head -n -1"
        ret = self.run_command(command)
        ret = ret.split('\n')
        chs = []
        for v in ret:
            try:
                tmp = int(v)
                tmp_ch = self.wifi_helper.translateFrequencyToChannel(tmp)

                if restrict5Ghz:
                    if tmp_ch > 14:
                        chs.append(tmp_ch)
                else:
                    chs.append(tmp_ch)
            except ValueError:
                pass
        self.log.debug('ResFi: chs %s' % str(chs))
        return chs
        
        
    """
        Get List of used channels
    """
    def getScanResults(self, restrict5Ghz=False):
        dev_name = config.WIRELESS_INTERFACE
        command = "sudo ../iw-4.3/iw dev " + dev_name + " scan ap-force | grep 'SSID\|freq\|signal'"
        ret = self.run_command(command)
        ret = ret.split('\n') 
        res = {}
        for t in ret:
           try:
               #print(t)
               arr = t.strip().split(':')
               if (len(arr) >=2):
                   k = arr[0].strip()
                   v = arr[1].strip()
                   #print('%s -> %s' % (k,v))
                   if k == 'freq':
                       # translate freq to channel
                       ch = self.wifi_helper.translateFrequencyToChannel(int(v))
                       if int(ch) < 14:
                           if restrict5Ghz:
                               pass
                           else:	   
                               if ch in res:
                                   res[ch] = res[ch] + 1
                               else:
                                   res[ch] = 1
                       else:
                           if ch in res:
                               res[ch] = res[ch] + 1
                           else:
                               res[ch] = 1           
           except ValueError:
               print('Error')     
        return res

    """
        The network load on an AP:
        - 0 = number of served client stations
    """
    def getNetworkLoad(self):
        num_stas = len(self.getInfoOfAssociatedSTAs())
        return num_stas

    """
        Information about associated STAs. The return value has the following structure:
        mac_addr -> stat_key -> list of (value, unit)
    """
    def getInfoOfAssociatedSTAs(self):
        try:
            command = 'iw dev ' + config.WIRELESS_INTERFACE + ' station dump'
            sout = self.run_command(command)

            # mac_addr -> stat_key -> list of (value, unit)
            res = {}
            sout_arr = sout.split("\n")

            for line in sout_arr:
                s = line.strip()
                if s == '':
                    continue
                if "Station" in s:
                    arr = s.split()
                    mac_addr = arr[1].strip()
                    res[mac_addr] = {}
                else:
                    arr = s.split(":")
                    key = arr[0].strip()
                    val = arr[1].strip()
                    arr2 = val.split()
                    val2 = arr2[0].strip()
                    if len(arr2) > 1:
                        unit = arr2[1].strip()
                    else:
                        unit = None
                    res[mac_addr][key] = (val2, unit)
            return res
        except Exception as e:
            raise Exception("An error occurred: %s" % e)

'''
    Connector module for the Mininet emulator implementing the southbound API.
'''
class MininetConnector(AbstractConnector):
    def __init__(self, log):
        AbstractConnector.__init__(self, log)

    # ResFiSouthBoundAPI
    def addIEtoProbeResponses(self, pubKeyStr, SymKeyStr, SymIVStr, IpStr):
        self.log.debug('Mininet:: program IE in probe response ... ')
        self.log.debug("EncryptKey: %s " % str(SymKeyStr))
        self.log.debug("Encrypt IV: %s" % str(SymIVStr))
        self.log.debug("Pub KEY: %s" % str(pubKeyStr))
        self.log.debug("IP: %s" % str(IpStr))
        self.probeResponseContent =  "\t Vendor specific: OUI b1:6b:00, data: b5 " + SymKeyStr + SymIVStr + pubKeyStr + IpStr
        self.log.debug("Probe Respone content: %s" % str(self.probeResponseContent))

    # ResFiSouthBoundAPI
    def performActiveScan(self, fullScan, ssid, freq, pubKeyStr, SymKeyStr, SymIVStr, IpStr, ownFreq):
        self.log.debug('Mininet::  performActiveScan()')
        # def scanSimulator(self):
        neighborList = {}
        ifs = self.getInterfaceList()
        ips = self.getIPList()
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        s.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, 1)
        timeout = time.time() + 1
        dataArray = []
        if fullScan:
            vProbeReq = "B16B00B5" + SymKeyStr + SymIVStr + pubKeyStr + IpStr + "B16B00B5" + str(ownFreq)
        else:
            vProbeReq = ''
        scanResult = ''
        addressList = []
        for i in ifs:
            sendip = self.network_helper.format_ip(i[1])
            if sendip == self.getHostname(): continue  # dont send simulation probes
            if sendip == "127.0.0.1": continue
            s.setsockopt(sock.SOL_SOCKET, sock.SO_BROADCAST, sock.inet_aton(sendip))
            ip_parts = sendip.split(".")
            ip_broad = ip_parts[0] + "." + ip_parts[1] + "." + ip_parts[2] + "." + "255"
            self.log.debug("Sending to Broadcast IP: " + str(ip_broad))
            s.sendto(vProbeReq, (ip_broad, config.SCAN_SIMU_PORT))
            s.setblocking(0)
            while True:
                try:
                    vProbeResp, address = s.recvfrom(8192)
                except:
                    time.sleep(0.001)
                    if time.time() > timeout: break
                    continue
                if str(address[0]) not in addressList and str(address[0]) not in ips and len(vProbeResp) > 0:
                    self.log.debug('Mininet:: Got virtual Probe Response from %s' % str(address))
                    self.log.debug('Mininet:: performActiveScan: Data : %s' % str(vProbeResp))
                    scanResult = str(vProbeResp)
                    addressList.append(str(address[0]))
                    cnt = 0
                    for line in scanResult.splitlines():
                        cnt = cnt +1
                        freq = 99
                        rssi = 999
                        ssid = "MininetVirtualAP"
                        if "Vendor specific: OUI b1:6b:00, data: b5 " in line:
                            line = line.replace("Vendor specific: OUI b1:6b:00, data: b5 ", "")
                            entry = freq, ssid, rssi, line
                            dataArray.append(entry)

        if len(dataArray) > 0:
            for i in range(0, len(dataArray)):
                entryTemp = dataArray[i]
                freqTemp = entryTemp[0]
                ssidTemp = entryTemp[1]
                rssiTemp = entryTemp[2]
                data = entryTemp[3]
                self.log.debug(data)
                if not isinstance(data, str):
                    continue
                elif len(data) <= 10:
                    continue
                data = data.replace(" ", "")
                data = data.replace("\n", "")
                data = data.replace("\t", "")
                self.log.debug(data)
                newNeighborEntry = self.parsing_helper.parse_resfi_ie(data, len(SymKeyStr), len(SymIVStr),
                                                                      len(pubKeyStr), 0, int(rssiTemp), int(freqTemp),
                                                                      ssidTemp)
                if newNeighborEntry.ipAddress == "Error":
                    continue

                neighborList[newNeighborEntry.ipAddress] = newNeighborEntry
        else:
            self.log.info("No neighbor APs found...")

        return neighborList

    # ResFiSouthBoundAPI
    def subscribeToProbeRequests(self, callback):
        self.log.debug('Mininet::  subscribeToProbeRequests()')
        port = config.SCAN_SIMU_PORT
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        s.bind(('', port))
        ips = self.getIPList()
        while True:
            message, address = s.recvfrom(8192)
            if str(address[0]) not in ips:
                self.log.debug('Mininet:: subscribeToProbeRequests: Got data from %s' % str(address))
                self.log.debug( 'Data: %s' % str(message))
                sent = s.sendto(self.probeResponseContent, address)
                callback(message, "999")

    def getMnNodeName(self):
        command = 'ifconfig'
        ret = self.run_command(command)
        nodename = ret.split("-eth0")
        return nodename[0]

    def getAPparams(self):
        channel = 100
        freq = 5500
        bssid = "XX:XX:XX:XX:XX:XX"
        ssid = str(self.getHostname()) + "-virtual-SSID"
        params = {'channel': channel, 'bssid': bssid, 'ssid': ssid, 'freq': freq}
        return params

    def getAvailableChannels(self, restrict5Ghz=False):
        chs = [140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 183, 184, 185, 187, 188, 189, 192, 196]
        return chs


    def getNetworkLoad(self):
        return 1

    """
        Set radio channel of AP
    """
    def setChannel(self, freq):
        self.freq = freq
        self.channel = self.wifi_helper.translateFrequencyToChannel(freq)
        return 'OK'

    def getChannel(self):
        if self.channel == 0:
            self.getAPparams()
        return self.channel

    """
    Information about associated STAs. The return value has the following structure:
    mac_addr -> stat_key -> list of (value, unit)
    """
    def getInfoOfAssociatedSTAs(self):
        # mac_addr -> stat_key -> list of (value, unit)
        res = {}
        for i in range(2):
            mac_addr=self.getHostname()+":i"
            val2 = len(self.getHostname())
            unit = "virtual"
            key = i
            res[mac_addr][key] = (val2, unit)
        return res

    def getInterfaceList(self):
        max_possible = 128  # arbitrary. raise if needed.
        bytes = max_possible * 32
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = \
        struct.unpack('iL', fcntl.ioctl(s.fileno(), 0x8912, struct.pack('iL', bytes, names.buffer_info()[0])))[0]
        namestr = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
           name = namestr[i:i + 16].split('\0', 1)[0]
           ip = namestr[i + 20:i + 24]
           lst.append((name, ip))
        return lst

    def getIPList(self):
        ips = []  # list of all ips
        for i in self.getInterfaceList():
           ips.append(self.network_helper.format_ip(i[1]))
        return ips

    def getWiredInterface(self):
        inter = self.getMnNodeName() + "-eth0"
        return inter

    def getHostname(self):
        return ni.ifaddresses(self.getWiredInterface())[2][0]['addr']

