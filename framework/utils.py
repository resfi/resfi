"""
    ResFi utilities

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

import sys
import time
import socket as sock
import fcntl
import struct
import array
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
import config
import threading
from Crypto.Cipher import PKCS1_OAEP
from threading import Thread


"""
    Helper class used for all string parsing related operations.
"""
class ParsingHelper:

    def __init__(self, log):
        self.debug = config.DEBUG
        self.log = log

    def parse_resfi_ie(self, data, SymKeyStrLen, SymIVStrLen, pubKeyStrLen, rssiProbeRequest, rssiProbeResponse, freq, ssid):

        newNeighborEntry = Neighbor()

        encryptionKeyNeighbor=data[:-(len(data)-SymKeyStrLen)]
        encryptionIVNeighbor=data[SymKeyStrLen:-(len(data)-SymKeyStrLen-SymIVStrLen)]
        pubKeyNeighbor = data[SymKeyStrLen+SymIVStrLen:-(len(data)-SymKeyStrLen-SymIVStrLen-pubKeyStrLen)]
        ipNeighbor = data[SymKeyStrLen+SymIVStrLen+pubKeyStrLen:]

        self.log.debug("EncryptKey: %s" % str(encryptionKeyNeighbor))
        self.log.debug("Encrypt IV %s: "% str(encryptionIVNeighbor))
        self.log.debug("Pub KEY: %s" % str(pubKeyNeighbor))
        self.log.debug("IP: %s" % str(ipNeighbor))
        self.log.debug("In ASCII:")
        if (len(encryptionKeyNeighbor)%2) != 0 or (len(encryptionIVNeighbor)%2) != 0 :
            self.log.debug("Received Key or IV is odd, not usable")
            newNeighborEntry.ipAddress = "Error"
            return newNeighborEntry

        rsona = encryptionKeyNeighbor.decode("hex")
        rstna = encryptionIVNeighbor.decode("hex")
        pkey = pubKeyNeighbor.decode("hex")
        ipna = ipNeighbor.decode("hex")

        self.log.debug(ipna)

        newNeighborEntry.ipAddress = ipna
        newNeighborEntry.encryptionKey = rsona
        newNeighborEntry.encryptionIV = rstna
        newNeighborEntry.pubKey = RSA.importKey(pkey)
        if rssiProbeRequest != 0:
            self.log.debug("rssiProbeRequest: %s" % str(rssiProbeRequest))
            newNeighborEntry.rssiProbeRequest = rssiProbeRequest
        if rssiProbeResponse != 0:
            self.log.debug("rssiProbeResponse: %s " % str(rssiProbeResponse))
            newNeighborEntry.rssiProbeResponse = rssiProbeResponse
        if freq != 0:
            self.log.debug("freq: %s" % str(freq))
            newNeighborEntry.freq = freq
        if ssid != 0:
            self.log.debug("ssid: %s" % str(ssid))
            newNeighborEntry.ssid = ssid

        return newNeighborEntry

    def parse_existing_neighbor(self, neighborEntry, neighborList):
        self.log.debug("Updating Neighbor: %s"  % str(neighborEntry.ipAddress))
        if len(neighborEntry.encryptionKey)>0:
            self.log.debug("Updating encryptionKey")
            neighborList[neighborEntry.ipAddress].encryptionKey = neighborEntry.encryptionKey
        if len(neighborEntry.encryptionIV)>0:
            self.log.debug("Updating encryptionIV")
            neighborList[neighborEntry.ipAddress].encryptionIV = neighborEntry.encryptionIV
        if len(str(neighborEntry.pubKey)) > 0:
            self.log.debug("Updating pubKey")
            neighborList[neighborEntry.ipAddress].pubKey = neighborEntry.pubKey
        if len(neighborEntry.ssid)>0:
            self.log.debug("Updating ssid")
            neighborList[neighborEntry.ipAddress].ssid = neighborEntry.ssid
        if neighborEntry.freq != 0:
            self.log.debug("Updating freq")
            neighborList[neighborEntry.ipAddress].freq = neighborEntry.freq
        if neighborEntry.rssiProbeRequest != 0:
            self.log.debug("Updating rssiProbeRequest")
            neighborList[neighborEntry.ipAddress].rssiProbeRequest = neighborEntry.rssiProbeRequest
        if neighborEntry.rssiProbeResponse != 0:
            self.log.debug("Updating rssiProbeResponse")
            neighborList[neighborEntry.ipAddress].rssiProbeResponse = neighborEntry.rssiProbeResponse
            self.log.debug("Updating timestampLastKCM")
            neighborList[neighborEntry.ipAddress].timestampLastKCM = neighborEntry.timestampLastKCM

        return neighborList

'''
    Object representing a direct AP neighbor, i.e. an AP in wireless communication range.
'''
class Neighbor:
    def __init__(self, mystr=str()):
        self.ipAddress = mystr
        self.encryptionKey = mystr
        self.encryptionIV = mystr
        self.pubKey = mystr
        self.freq = 0
        self.ssid = mystr
        self.rssiProbeRequest = 0
        self.rssiProbeResponse = 0
        self.timestampLastKCM = int(time.time())
        self.oldEncryptionKey = 0
        self.oldEncryptionIV = 0
        self.lostMessages = 0
        self.rxStatsLost = 0
        self.rxStatsSuccess = 0
        self.unicastSendKey = str()
        self.unicastSendIv = str()
        self.unicastRecKey = str()
        self.unicastRecIv = str()
        self.waitingForUnicastKeys = threading.Event()

"""
    Everything related to general networking.
"""
class NetworkHelper:
    def __init__(self, log):
        self.log = log

    def format_ip(self, addr):
        return str(ord(addr[0])) + '.' + \
               str(ord(addr[1])) + '.' + \
               str(ord(addr[2])) + '.' + \
               str(ord(addr[3]))

    def all_interfaces(self):
        max_possible = 128  # arbitrary. raise if needed.
        bytes = max_possible * 32
        s = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
        names = array.array('B', '\0' * bytes)
        outbytes = struct.unpack('iL', fcntl.ioctl(s.fileno(), 0x8912, struct.pack('iL', bytes, names.buffer_info()[0])))[0]
        namestr = names.tostring()
        lst = []
        for i in range(0, outbytes, 40):
            name = namestr[i:i+16].split('\0', 1)[0]
            ip  = namestr[i+20:i+24]
            lst.append((name, ip))
        return lst

"""
    Everything related to wireless networking.
"""
class WiFiHelper:
    def __init__(self, log):
        self.log = log
        self.initializeChannelToFrequencyArray()

    def translateChannelToFrequency(self, channel):
        try:
            ret = self.ch_to_freq[channel]
        except IndexError:
            ret = 0
        return ret

    def translateFrequencyToChannel(self, freq):
        try:
            for ch in range(len(self.ch_to_freq)):
                if self.ch_to_freq[ch] == freq:
                    return ch
            raise Exception('frequency unknown freq: ' + str(freq))
        except IndexError:
            ret = 0
        return ret

    def initializeChannelToFrequencyArray(self):
        self.ch_to_freq = [0 for x in range(200)]
        #self.ch_to_freq = []
        #self.ch_to_freq[7] = 5035
        #self.ch_to_freq[8] = 5040
        #self.ch_to_freq[9] = 5045
        #self.ch_to_freq[11] = 5055
        #self.ch_to_freq[12] = 5060
        #self.ch_to_freq[16] = 5080

        # 5 GHz
        self.ch_to_freq[36] = 5180
        self.ch_to_freq[38] = 5190
        self.ch_to_freq[40] = 5200
        self.ch_to_freq[42] = 5210
        self.ch_to_freq[44] = 5220
        self.ch_to_freq[46] = 5230
        self.ch_to_freq[48] = 5240
        self.ch_to_freq[52] = 5260
        self.ch_to_freq[54] = 5270
        self.ch_to_freq[56] = 5280
        self.ch_to_freq[58] = 5290
        self.ch_to_freq[60] = 5300
        self.ch_to_freq[62] = 5310
        self.ch_to_freq[64] = 5320
        self.ch_to_freq[100] = 5500
        self.ch_to_freq[102] = 5510
        self.ch_to_freq[104] = 5520
        self.ch_to_freq[106] = 5530
        self.ch_to_freq[108] = 5540
        self.ch_to_freq[110] = 5550
        self.ch_to_freq[112] = 5560
        self.ch_to_freq[114] = 5570
        self.ch_to_freq[116] = 5580
        self.ch_to_freq[118] = 5590
        self.ch_to_freq[120] = 5600
        self.ch_to_freq[122] = 5610
        self.ch_to_freq[124] = 5620
        self.ch_to_freq[126] = 5630
        self.ch_to_freq[128] = 5640
        self.ch_to_freq[132] = 5660
        self.ch_to_freq[134] = 5670
        self.ch_to_freq[136] = 5680
        self.ch_to_freq[138] = 5690
        self.ch_to_freq[140] = 5700
        self.ch_to_freq[142] = 5710
        self.ch_to_freq[144] = 5720
        self.ch_to_freq[149] = 5745
        self.ch_to_freq[151] = 5755
        self.ch_to_freq[153] = 5765
        self.ch_to_freq[155] = 5775
        self.ch_to_freq[157] = 5785
        self.ch_to_freq[159] = 5795
        self.ch_to_freq[161] = 5805
        self.ch_to_freq[165] = 5825
        self.ch_to_freq[183] = 4915
        self.ch_to_freq[184] = 4920
        self.ch_to_freq[185] = 4925
        self.ch_to_freq[187] = 4935
        self.ch_to_freq[188] = 4940
        self.ch_to_freq[189] = 4945
        self.ch_to_freq[192] = 4960
        self.ch_to_freq[196] = 4980

        # 2.4 GHz
        self.ch_to_freq[1] = 2412
        self.ch_to_freq[2] = 2417
        self.ch_to_freq[3] = 2422
        self.ch_to_freq[4] = 2427
        self.ch_to_freq[5] = 2432
        self.ch_to_freq[6] = 2437
        self.ch_to_freq[7] = 2442
        self.ch_to_freq[8] = 2447
        self.ch_to_freq[9] = 2452
        self.ch_to_freq[10] = 2457
        self.ch_to_freq[11] = 2462
        self.ch_to_freq[12] = 2467
        self.ch_to_freq[13] = 2472
        self.ch_to_freq[14] = 2484

    def hex_to_vendor_spec_ie(self, hexString, dotFormatted=False):
        if len(hexString) % 2 != 0:
            self.log.error("Wrong input format for hex_to_vendor_spec_ie() function")
            return -1
        if len(hexString) > (249*2):
            self.log.error("Too much data for one vendor specific IE")
            return -2
        dataLength = len(hexString)/2 + 4
        dataLengthHex = '{:02x}'.format(dataLength)
        if dotFormatted == True:
            hexStringDotted = str()
            iter = 1
            for c in hexString:
                if iter % 2 == 0:
                    hexStringDotted = hexStringDotted + str(c)+":"
                else:
                    hexStringDotted = hexStringDotted + str(c)
                iter = iter + 1

            vendorFormatted = "dd:"+str(dataLengthHex)+":"+"b1:6b:00:b5:"+ hexStringDotted[:-1]
        else:
            vendorFormatted = "dd"+str(dataLengthHex)+"b16b00b5"+str(hexString)

        return vendorFormatted

'''
    All the security stuff resides here.
'''
class SecurityHelper:
    def __init__(self, log):
        self.log = log

    def random_char(self, y):
        return ''.join(random.choice(string.ascii_letters) for x in range(y))

    def create_signature(self, data, key):
        msgHash = hashlib.sha1(repr(data)).digest()
        return key.sign(msgHash, '')

    #def createScanRequestSignature(self, data, key):
    #    return hashlib.sha1(repr(data) + "," + key).hexdigest()

    def verify_signature(self, signature, data, key):
        msgHash = hashlib.sha1(repr(data)).digest()
        return key.verify(msgHash, signature)

    #def verifyScanRequestSignature(self, signature, data, key):
    #    test = self.createScanRequestSignature(data, key)
    #    if test == signature:
    #        return True
    #    else:
    #        return False

    def generateSymmetricKeys(self):
        key = Random.new().read(16)
        keyHexStr = key.encode("hex")
        iv = Random.new().read(16)
        ivHexStr = iv.encode("hex")
        assert (len(key) == 16)
        assert (len(iv) == 16)
        return {'key':key, 'iv':iv, 'keyHexStr' : keyHexStr, 'ivHexStr':ivHexStr}

    def decrypt_with_private_key(self, rsaKey, assymEncrMessage):
        cipher = PKCS1_OAEP.new(rsaKey)
        plain = cipher.decrypt(assymEncrMessage)
        return plain


class ChannelSwitchGuardThread(Thread):
    def __init__(self):
        Thread.__init__(self)
        #self.stopped = event

    def run(self, lastKCM, guard, kcmInter, freq, channel, callback, finisher, channelOld, freqOld):
        while True:
            if (((int(time.time()) - lastKCM) > guard) and ((int(time.time()) - lastKCM) < (kcmInter-guard))):
                ret = callback(freq)
                finisher(ret, channel, freq, channelOld, freqOld)
                return
            time.sleep(0.001)    
