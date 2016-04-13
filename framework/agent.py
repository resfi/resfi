
"""
    The ResFi Agent class

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

from connectors import LinuxConnector, MininetConnector
from utils import WiFiHelper
from utils import NetworkHelper
from utils import SecurityHelper
from utils import Neighbor
from utils import ParsingHelper
from utils import ChannelSwitchGuardThread
from common.resfi_api import ResFiNorthBoundAPI
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import traceback
import zmq
import sys
import time
import threading
import os
import random
import config
import json


class ResFiAgent(ResFiNorthBoundAPI):

    def __init__(self, log):
        self.log = log
        self.debug = config.DEBUG
        self.lostMessages = 0 # TODO: do we need this?

        # use the proper connector module
        if config.CONNECTOR == "mininet":
            self.connector = MininetConnector(log)
        elif config.CONNECTOR == "linux":
            self.connector = LinuxConnector(log)

        # Helper Objects
        self.wifi_helper = WiFiHelper(log)
        self.network_helper = NetworkHelper(log)
        self.security_helper = SecurityHelper(log)
        self.parsing_helper = ParsingHelper(log)

        # Config
        self.FWD_PORT = config.FWD_PORT
        self.SND_PORT = config.SND_PORT
        self.SLEEP_DUR = config.SLEEP_DUR
        self.keyChangeInterval = config.KEYCHANGEINTERVAL

        #Internal RX Callback
        self.rx_cb = self.rxCbInternal

        #Init thread handling objects
        self.init_thread_handling()
        self.init_local_credentials()
        self.init_security_credentials()

        self.connector.addIEtoProbeResponses(self.pubKeyHexStr, self.keyHexStr, self.ivHexStr, self.hostnameStrHex)

        self.initSendMsg()

        # ResFi forwarding thread
        fwd_t = threading.Thread(name='initForwarding', target=self.initForwardingTTL)
        fwd_t.setDaemon(True)
        fwd_t.start()

        time.sleep(1)

        self.init_self_connection()

        scanResults = self.connector.performActiveScan(True, "", 0, self.pubKeyHexStr, self.keyHexStr, self.ivHexStr, self.hostnameStrHex, self.freq)
        self.onAPJoined(scanResults)

        # thread responsible for handling probe requests received by hostapd, takes callback for probe request handling
        probereq_t = threading.Thread(name='subscribeToProbeRequests', target=self.connector.subscribeToProbeRequests, args=(self.handle_incoming_probe_requests,))
        probereq_t.setDaemon(True)
        probereq_t.start()


        # receive message thread
        sub_t = threading.Thread(name='receiveMessage', target=self.receiveMessage, args=(self.rx_cb,))
        sub_t.setDaemon(True)
        sub_t.start()

        # periodic key changing
        keychanger_t = threading.Thread(name='changeKeys', target=self.changeKeys)
        keychanger_t.setDaemon(True)
        keychanger_t.start()

    """
    Init local credentials, e.g. AP params, interfaces
    """
    def init_local_credentials(self):

        #Initialize neighborList dict
        self.globalNeighborList = {}

         #Initialize appList dict
        self.globalAppList = {}

        self.publicInterface = self.connector.getWiredInterface()
        self.hostname = self.connector.getHostname()
        self.hostnameStrHex = self.hostname.encode("hex")
        self.ifs = self.connector.getInterfaceList()
        self.ips = self.connector.getIPList()

        self.log.info("ResFi: IPS: %s" % str(self.ips))
        self.log.info("ResFi: IFS: %s" % str(self.ifs))
        self.log.info("ResFi: Hostname: %s" % str(self.hostname))

        self.apParams = self.connector.getAPparams()
        self.channel = self.apParams['channel']
        self.freq = self.apParams['freq']
        self.bssid = self.apParams['bssid']
        self.ssid = self.apParams['ssid']
        self.log.info("ResFi: BSSID: %s SSID: %s Channel: %s Frequency: %s" % (str(self.bssid), str(self.ssid), str(self.channel), str(self.freq)))

    """
    Init thread_handling, e.g. event variables ...
    """
    def init_thread_handling(self):
    #Thread Handling
        self.processingProbeRequestEvent = threading.Event()
        self.processingChangeKeysEvent = threading.Event()
        self.sendingUserSpaceMessageEvent = threading.Event()
        self.sendingUserCtrlMessageEvent = threading.Event()
        self.processingNeighborUpdateEvent = threading.Event()
        self.processingNeighborMessageEvent = threading.Event()
        self.processingChannelSwitchEvent = threading.Event()

        self.processingProbeRequestEvent.set()
        self.processingChangeKeysEvent.set()
        self.sendingUserSpaceMessageEvent.set()
        self.sendingUserCtrlMessageEvent.set()
        self.processingNeighborUpdateEvent.set()
        self.processingNeighborMessageEvent.set()
        self.processingChannelSwitchEvent.set()

    """
    Init security credentials, e.g. security keys, self connection, ...
    """
    def init_security_credentials(self):
        self.init_public_security_credentials()
        self.init_symmetric_security_credentials()

    def init_public_security_credentials(self):
        #RSA Keys
        self.rsaKey = RSA.generate(1024, os.urandom)
        self.pubKey = self.rsaKey.publickey()
        self.pubKeyHexStr = self.pubKey.exportKey('DER').encode("hex")

    def init_symmetric_security_credentials(self):
        #AES Keys
        keys = self.security_helper.generateSymmetricKeys()
        self.key = keys['key']
        self.keyHexStr = keys['keyHexStr']
        self.iv = keys['iv']
        self.ivHexStr = keys['ivHexStr']

    """
    Init self connection
    """
    def init_self_connection(self):
        #Add myself to neighbors
        ownNeighborEntry = Neighbor()
        ownNeighborEntry.ipAddress = self.hostname
        ownNeighborEntry.encryptionKey = self.key
        ownNeighborEntry.encryptionIV = self.iv
        #Connect to own socket
        tempNeighborList = {}
        tempNeighborList[self.hostname] = ownNeighborEntry
        self.onAPJoined(tempNeighborList)


    """
    Forwarding while considering TTL, packet ID, ...
    """
    def initForwardingTTL(self):
        self.log.debug('initForwarding_ttl')
        try:
            context = zmq.Context(1)
            # Socket facing clients
            self.frontend = context.socket(zmq.SUB)

            self.frontend.setsockopt(zmq.SUBSCRIBE, "")

            # Socket facing services
            self.backend = context.socket(zmq.PUB)
            self.backend.bind("tcp://*:%s" % self.FWD_PORT)

            fwd_cache = {}
            while True:
                json_data = self.frontend.recv_json()
                # update ttl
                json_data['ttl'] = int(json_data['ttl']) - 1
                if json_data['ttl'] <= 0:
                    time.sleep(self.SLEEP_DUR)
                    continue
                if json_data['host'] in fwd_cache and fwd_cache[json_data['host']] >= json_data['id']:
                    time.sleep(self.SLEEP_DUR)
                    continue
                if json_data['host'] != self.hostname and json_data['rec'] != "255.255.255.255" and json_data['rec'] != self.hostname:
                    time.sleep(self.SLEEP_DUR)
                    continue

                self.log.debug("Forwarder received message...")
                self.log.debug("Forwarder waiting for ProbeRequestevent..")
                self.processingProbeRequestEvent.wait()

                self.log.debug("Forwarder waiting for ProcessingChangeKeysEvent..")
                self.processingChangeKeysEvent.wait()

                self.log.debug("Forwarder waiting for ProcessingNeighborUpdateEvent..")
                self.processingNeighborUpdateEvent.wait()

                self.log.debug("Forwarder is running...")

                if json_data['host'] != self.hostname:
                    isNeighborMessage = True
                    self.log.debug("Forwarder is handling Message from Neighbor: %s original sender: %s" % (str(json_data['lasthop']), str(json_data['host'])))
                    self.processingNeighborMessageEvent.clear()
                else:
                    isNeighborMessage = False
                    self.log.debug("Forwarder is handling own outgoing Message: %s original sender: %s" % (str(json_data['lasthop']), str(json_data['host'])))

                if (json_data['lasthop'] in self.globalNeighborList):
                    lasthop_key = self.globalNeighborList[json_data['lasthop']].encryptionKey
                    lasthop_iv = self.globalNeighborList[json_data['lasthop']].encryptionIV
                    if json_data['lasthop'] != self.hostname and json_data['lasthop'] != 'old_keys':
                        pubKey = self.globalNeighborList[json_data['lasthop']].pubKey
                    else:
                        pubKey = self.rsaKey
                    lasthop_aes = AES.new(lasthop_key, AES.MODE_CFB, lasthop_iv)
                    enc_message_byte = base64.decodestring(json_data['msg'])
                    plain_msg = lasthop_aes.decrypt(enc_message_byte)

                    self.log.debug("From: %s" % str(json_data['lasthop']))
                    sig = json_data['sig']
                    success = False
                    if not self.security_helper.verify_signature(sig, plain_msg, pubKey):
                        self.log.debug("Signature mismatch trying with old keys if possible...")
                        if isNeighborMessage == False:
                            self.log.debug("Decrypting own message failed....")
                            self.sendingUserSpaceMessageEvent.set()
                            self.sendingUserCtrlMessageEvent.set()
                            continue
                        if self.globalNeighborList[json_data['lasthop']].oldEncryptionKey != 0 and self.globalNeighborList[json_data['lasthop']].oldEncryptionIV != 0:
                            lasthop_aes = AES.new(self.globalNeighborList[json_data['lasthop']].oldEncryptionKey, AES.MODE_CFB, self.globalNeighborList[json_data['lasthop']].oldEncryptionIV)
                            enc_message_byte = base64.decodestring(json_data['msg'])
                            plain_msg = lasthop_aes.decrypt(enc_message_byte)
                            #print "Message old key try: "+str(plain_msg)+ " From: "+str(json_data['lasthop'])
                            sig = json_data['sig']
                            if not self.security_helper.verify_signature(sig, plain_msg, pubKey):
                                success = False
                                self.log.debug("Decrypting with old keys failed")
                            else:
                                success = True
                                self.log.debug("Old keys worked")
                        else:
                            success = False
                            self.log.debug("No old keys available")
                        if success == False:
                            self.log.debug("No Old keys available or signature mismatch with old keys...")
                            self.log.debug("Trying to pause neighbor message processing to allow finishing of KCM process...")
                            self.processingNeighborMessageEvent.set()

                            #self.sendingUserSpaceMessageEvent.wait()
                            #self.sendingUserCtrlMessageEvent.wait()
                            self.processingNeighborUpdateEvent.wait()
                            self.processingProbeRequestEvent.wait()
                            self.processingChangeKeysEvent.wait()
                            self.processingNeighborMessageEvent.clear()

                            self.log.debug("Now trying again with hopefully new keys....")

                            lasthop_aes = AES.new(lasthop_key, AES.MODE_CFB, lasthop_iv)
                            enc_message_byte = base64.decodestring(json_data['msg'])
                            plain_msg = lasthop_aes.decrypt(enc_message_byte)
                            sig = json_data['sig']
                            if not self.security_helper.verify_signature(sig, plain_msg, pubKey):
                                self.globalNeighborList[json_data['lasthop']].lostMessages = self.globalNeighborList[json_data['lasthop']].lostMessages + 1
                                self.globalNeighborList[json_data['lasthop']].rxStatsLost = self.globalNeighborList[json_data['lasthop']].rxStatsLost + 1

                                self.log.debug("Lost Messages Counter: %s" % str(self.globalNeighborList[json_data['lasthop']].lostMessages))
                                self.log.debug("Lost Messages Overall: %s" % str(self.globalNeighborList[json_data['lasthop']].rxStatsLost))
                                self.log.debug("Overall Messages Received from Neighbor: %s" % str(self.globalNeighborList[json_data['lasthop']].rxStatsSuccess))

                                if self.globalNeighborList[json_data['lasthop']].lostMessages >= 5:
                                    self.log.debug("Decrypting of neighbor messages failed %s times, trying to rescan neighbor" % (str(self.globalNeighborList[json_data['lasthop']].lostMessages)))
                                    self.globalNeighborList[json_data['lasthop']].lostMessages = 0
                                    if self.globalNeighborList[json_data['lasthop']].freq != 0:
                                        self.log.debug("Trying Rescanning Neighbor, waiting for other KCM processes...")
                                        self.processingNeighborMessageEvent.set()
                                        self.processingNeighborUpdateEvent.wait()
                                        self.processingProbeRequestEvent.wait()
                                        self.processingChangeKeysEvent.wait()
                                        self.processingNeighborUpdateEvent.clear()
                                        freq = self.globalNeighborList[json_data['lasthop']].freq
                                        ssid = self.globalNeighborList[json_data["lasthop"]].ssid
                                        self.rescan_neighbor(freq, ssid, json_data['lasthop'], 10)
                                        self.processingNeighborUpdateEvent.set()
                                        continue
                                        #self.processingNeighborMessageEvent.set()
                                    else:
                                        self.log.debug("No frequency or SSID of neighbor available")
                                        self.onAPLeft(json_data['lasthop'], "No frequency or SSID of neighbor available")
                                        self.processingNeighborMessageEvent.set()
                                        continue
                                else:
                                    self.processingNeighborMessageEvent.set()
                                    continue

                    if json_data['lasthop'] == 'old_keys':
                        sendKey=lasthop_key
                        sendIv=lasthop_iv
                    else:
                        sendKey=self.key
                        sendIv=self.iv

                    #append own signature
                    sig = self.security_helper.create_signature(plain_msg, self.rsaKey)
                    json_data['sig'] = sig
                    # encrypt with my own key
                    aes = AES.new(sendKey, AES.MODE_CFB, sendIv)
                    new_message = aes.encrypt(plain_msg)
                    new_message_b64 = base64.encodestring(new_message)
                    json_data['msg'] = new_message_b64
                    if isNeighborMessage == True:
                        self.log.debug("Resetting lost messages counter of neighbor")
                        self.globalNeighborList[json_data['lasthop']].lostMessages = 0
                        self.log.debug("Incrementing overall neighbor messsage cntr")
                        self.globalNeighborList[json_data['lasthop']].rxStatsSuccess = self.globalNeighborList[json_data['lasthop']].rxStatsSuccess + 1
                    # update last hop
                    json_data['lasthop'] = self.hostname

                    self.backend.send_json(json_data)
                    fwd_cache[json_data['host']] = json_data['id']
                    if json_data['host'] == self.hostname:#
                        self.log.debug("Forwarder: Own Message sent from: %s" % str(json_data['lasthop']))
                        self.sendingUserSpaceMessageEvent.set()
                        self.sendingUserCtrlMessageEvent.set()
                    else:
                        self.log.debug("Forwarder: Neighbor Message forwarded from: %s" % str(json_data['lasthop']))
                    time.sleep(self.SLEEP_DUR)
                else:
                    self.log.debug("fwd::cannot decode from %s; drop message" % (json_data['host']))

        except Exception as e:
            traceback.print_exc()
            self.log.error("bringing down zmq device %s" % str(sys.exc_info()[0]))
        finally:
            pass
            self.frontend.close()
            self.backend.close()
            context.term()

    """
    Example message source to be disseminated
    """
    def initSendMsg(self):
        self.log.debug('initSendMsg')
        context = zmq.Context()
        self.snd_socket = context.socket(zmq.PUB)
        self.snd_socket.bind("tcp://*:%s" % self.SND_PORT)
        self.local_id = 1

    """
    Receive Probe Requests from hostapd and handle them
    """
    def handle_incoming_probe_requests(self, payload, rssi):
        self.log.debug("ResFi: handle_incoming_probe_requests")
        self.log.debug("ResFi: payload: %s" % payload )
        if 'B16B00B5' in payload:
            resfiIe = payload.split('B16B00B5',2)[1]
            resfiIe = resfiIe.replace('DD06', '')
            resfiFreq = payload.split('B16B00B5',2)[2]
            freq = int(resfiFreq) 
            self.log.info("ResFi: resfiFreq: %s" % str(freq) )
            self.log.debug("ResFi: Incoming ResFi Probe Request")
            self.log.debug(resfiIe)
            self.processingChangeKeysEvent.wait()
            self.processingNeighborUpdateEvent.wait()
            self.sendingUserSpaceMessageEvent.wait()
            self.sendingUserCtrlMessageEvent.wait()
            self.processingProbeRequestEvent.clear()
            newNeighbor = self.parsing_helper.parse_resfi_ie(resfiIe, len(self.keyHexStr), len(self.ivHexStr), len(self.pubKeyHexStr), int(rssi), 0, freq, 0)
            neighborList = {}
            neighborList[newNeighbor.ipAddress] = newNeighbor
            self.onAPJoined(neighborList)
            self.processingProbeRequestEvent.set()
        # # self.keyLock.release()
        #print"Receive Probe Requests Thread Released # # self.keyLock.release()"

    """
    Receive message
    """
    def receiveMessage(self, myCallback):
        self.log.debug('receiveMessage')
        # Socket to talk to server
        context = zmq.Context()
        socket = context.socket(zmq.SUB)
        socket.connect ("tcp://%s:%s" % (self.hostname, self.FWD_PORT))
        socket.setsockopt(zmq.SUBSCRIBE, "")
        while True:
            json_data = socket.recv_json()
            if json_data['host'] == self.hostname:
                continue
            #decode
            encoded = base64.decodestring(json_data['msg'])
            aes = AES.new(self.key, AES.MODE_CFB, self.iv)
            plain = aes.decrypt(encoded)
            sig = json_data['sig']
            if not self.security_helper.verify_signature(sig, plain, self.rsaKey):
                self.log.debug("Signature mismatch while checking own signature...")
                continue

            if json_data['rec'] != "255.255.255.255" and json_data['rec'] == self.hostname and json_data['msg_type'] == "ctrl":
                assymEncrMessage = plain
                plain = self.security_helper.decrypt_with_private_key(self.rsaKey, assymEncrMessage)
                self.log.debug('Received unicast CTRL message from: %s with subtype %s' % (json_data['host'], json_data['sub_type']))

            elif json_data['rec'] != "255.255.255.255" and json_data['rec'] == self.hostname and json_data['msg_type'] == "data":
                if json_data['rec'] in self.globalNeighborList:
                    plain_encoded = base64.decodestring(plain)
                    if self.globalNeighborList[json_data['host']].unicastRecKey == str():
                        self.log.warn('Unicast Message from neighbor %s could not be decoded, no unicast key available' % (json_data['rec']))
                        continue
                    aes = AES.new(self.globalNeighborList[json_data['host']].unicastRecKey, AES.MODE_CFB, self.globalNeighborList[json_data['host']].unicastRecIv)
                    plain = aes.decrypt(plain_encoded)
                    self.log.debug('Unicast Message from neighbor %s decoded' % (json_data['rec']))

            self.log.debug('rx plain |%s|' % (plain))
            self.processingNeighborMessageEvent.set()
            json_data['msg'] = unicode(plain, errors='ignore')
            #If the message is a control message
            if json_data['msg_type'] == 'ctrl':
                self.log.debug("Received CTRL Message")
                timestampKCM = int(time.time())
                #if the message is a key change message
                if json_data['sub_type'] == 'kcm':
                    self.log.debug("Received CTRL Message waiting for sendingUserSpaceMessageEvent")
                    self.sendingUserSpaceMessageEvent.wait()
                    self.log.debug("Received CTRL Message waiting for sendingUserCtrlMessageEvent")
                    self.sendingUserCtrlMessageEvent.wait()
                    self.log.debug("Received CTRL Message waiting for processingProbeRequestEvent")
                    self.processingProbeRequestEvent.wait()
                    self.log.debug("Received CTRL Message waiting for processingChangeKeysEvent")
                    self.processingChangeKeysEvent.wait()
                    self.log.debug("Received CTRL Message waiting for processingNeighborMessageEvent")
                    self.processingNeighborMessageEvent.wait()
                    self.log.debug("Received CTRL Message clearing processingNeighborUpdateEvent")
                    self.processingNeighborUpdateEvent.clear()
                    self.log.debug("Received CTRL Message running....")
                    plain_splitted = json_data['msg'].split('|')
                    freq = int(plain_splitted[0])
                    ssid = plain_splitted[1]
                    ipAddress = plain_splitted[2]

                    self.log.debug("Received key change message (KCM): ssid: %s, freq: %s " % (str(ssid), str(freq)))
                    if (json_data["host"] in self.globalNeighborList):
                        newNeighborEntry = Neighbor()
                        newNeighborEntry.ipAddress = ipAddress
                        newNeighborEntry.freq = freq
                        newNeighborEntry.ssid = ssid
                        newNeighborEntry.timestampLastKCM = timestampKCM
                        self.globalNeighborList = self.parsing_helper.parse_existing_neighbor(newNeighborEntry, self.globalNeighborList)
                        self.rescan_neighbor(freq, ssid, ipAddress, 10)
                    self.processingNeighborUpdateEvent.set()
                #if the message is a request unicast key message
                elif json_data['sub_type'] == 'ruk':
                    self.log.debug("Received request for unicast key (RUK) CTRL Message")
                    #generate unicast symmetric key and send them back.
                    if (json_data["host"] in self.globalNeighborList):
                        if len(self.globalNeighborList[json_data["host"]].unicastRecKey)>2:
                            retMsg = json.dumps({"key" : str(self.globalNeighborList[json_data["host"]].unicastRecKey.encode('hex')), "iv" : str(self.globalNeighborList[json_data["host"]].unicastRecIv.encode('hex'))})
                            self.sendCtrlToNeighbor(retMsg, "nuk", str(), str(), json_data["host"])
                        else:
                            keys = self.security_helper.generateSymmetricKeys()
                            retMsg = json.dumps({"key" : str(keys['keyHexStr']), "iv" : str(keys['ivHexStr'])})
                            self.sendCtrlToNeighbor(retMsg, "nuk", str(), str(), json_data["host"])
                            self.globalNeighborList[json_data["host"]].unicastRecKey = keys['key']
                            self.globalNeighborList[json_data["host"]].unicastRecIv = keys['iv']
                    else:
                        self.log.warn("Unkown neighbor requested symmetric unicast keys")
                elif json_data['sub_type'] == 'nuk':
                    self.log.debug("Received new unicast key (NUK) CTRL Message")
                    if (json_data["host"] in self.globalNeighborList):
                        nukMsg = json.loads(json_data['msg'])
                        self.globalNeighborList[json_data["host"]].unicastSendKey = nukMsg["key"].decode('hex')
                        self.globalNeighborList[json_data["host"]].unicastSendIv = nukMsg["iv"].decode('hex')
                        self.globalNeighborList[json_data["host"]].waitingForUnicastKeys.set()

            else:
                myCallback(json_data)


    def rescan_neighbor(self, freq, ssid, host, retries):
        maxRetries = retries
        found = False
        for cc in range(0, maxRetries):
            scanResults = self.connector.performActiveScan(False, ssid, freq, self.pubKeyHexStr, self.keyHexStr, self.ivHexStr, self.hostname, 0)
            for key in scanResults:
                if scanResults[key].ipAddress == host:
                    if str(scanResults[key].encryptionKey.encode("hex")) != str(self.globalNeighborList[host].encryptionKey.encode("hex")):
                        if self.debug:
                            self.log.debug("New key for %s successfully received" % str(host))
                            self.log.debug("Old Key: %s" % str(self.globalNeighborList[host].encryptionKey.encode("hex")))
                            self.log.debug("new Key: %s" % str(scanResults[key].encryptionKey.encode("hex")))
                        self.globalNeighborList[host].oldEncryptionKey = self.globalNeighborList[host].encryptionKey
                        self.globalNeighborList[host].oldEncryptionIV = self.globalNeighborList[host].encryptionIV
                        tempNeighborList = {}
                        tempNeighborList[scanResults[key].ipAddress] = scanResults[key]
                        self.onAPJoined(tempNeighborList)
                        found = True
                    else:
                        self.log.debug("ScanResults include old key, retry!")
            if found == True:
                break
            else:
                self.log.debug("Scan Retry triggered")
                time.sleep(random.uniform(0,0.2))
        if cc == (maxRetries-1):
            self.log.debug("Max retries reached, neighbor removed.")
            self.onAPLeft(host, "Max rescan retries reached, neighbor removed")
            return False
        return True

    """
    Neighbor Handling
    """
    def onAPJoined(self, scanResultList):

        for key in scanResultList:
            adjacentNode = scanResultList[key].ipAddress
            # connect to peer
            try:
                if (adjacentNode in self.globalNeighborList):
                    self.globalNeighborList = self.parsing_helper.parse_existing_neighbor(scanResultList[key], self.globalNeighborList)
                else:
                    if adjacentNode == self.hostname:
                        tmp_port = self.SND_PORT
                    else:
                        tmp_port = self.FWD_PORT
                    self.log.info("ResFi: Now connecting to: %s on port: %s" % (str(adjacentNode), str(tmp_port)))
                    self.frontend.connect("tcp://%s:%s" % (adjacentNode, tmp_port))
                    self.globalNeighborList[adjacentNode] = scanResultList[key]
                    for ns in self.globalAppList:
                        self.processingProbeRequestEvent.set()
                        self.log.debug("Notifying Application: %s" % str(ns))
                        self.globalAppList[ns].newLink_cb(adjacentNode)
            except Exception as e:
                self.log.error(e)
                self.log.error("onAPJoined failed")

    def onAPLeft(self, adjacentNode, reason):
        tmp_port = self.FWD_PORT
        self.log.info("ResFi: Removing neighbor %s and connection on port: %s REASON: %s" % (str(adjacentNode), str(tmp_port), str(reason)))
        self.frontend.disconnect("tcp://%s:%s" % (adjacentNode, tmp_port))
        del self.globalNeighborList[adjacentNode]
        self.log.debug("ResFi: neighbor removed.")
        for ns in self.globalAppList:
            self.log.debug("Notifying Application: %s" % str(ns))
            self.globalAppList[ns].linkFailure_cb(adjacentNode)

    """
    Key Change Thread
    """
    def changeKeys(self):
        #time.sleep(self.keyChangeInterval)
        while True:
            time.sleep(self.keyChangeInterval)
            self.sendingUserSpaceMessageEvent.wait()
            self.sendingUserCtrlMessageEvent.wait()
            self.processingProbeRequestEvent.wait()
            self.processingChangeKeysEvent.clear()
            message = str(self.freq)+"|"+str(self.ssid)+"|"+str(self.hostname)
            sub_type = "kcm"
            key_old = self.key
            iv_old = self.iv
            #Generate and change Keys
            self.init_symmetric_security_credentials()
            self.init_self_connection()
            self.connector.addIEtoProbeResponses(self.pubKeyHexStr, self.keyHexStr, self.ivHexStr, self.hostnameStrHex)
            #Send KCM to all OneHopNeigbors
            self.processingChangeKeysEvent.set()
            self.sendCtrlToNeighbors(message, sub_type, key_old, iv_old)
            self.globalNeighborList[self.hostname].timestampLastKCM = int(time.time())
            self.validateCurrentNeighborList()

    def validateCurrentNeighborList(self):
        self.processingProbeRequestEvent.wait()
        self.sendingUserSpaceMessageEvent.wait()
        self.sendingUserCtrlMessageEvent.wait()
        self.processingNeighborMessageEvent.wait()
        self.processingNeighborUpdateEvent.clear()
        timestampNow = int(time.time())
        expiredNeighbors = []

        self.log.debug("ResFi: Listing current neighbors stats: ")

        for key in self.globalNeighborList:
            if self.globalNeighborList[key].ipAddress != self.hostname:
                self.log.info("ResFi: [ %s (%s/%s), Lost %s/%s]"
                               % (self.globalNeighborList[key].ipAddress, self.globalNeighborList[key].ssid,
                                  str(self.globalNeighborList[key].freq), str(self.globalNeighborList[key].rxStatsLost),
                                  str(self.globalNeighborList[key].rxStatsSuccess)))

                if (timestampNow - self.globalNeighborList[key].timestampLastKCM) > (3*config.KEYCHANGEINTERVAL):
                    expiredNeighbors.append(self.globalNeighborList[key].ipAddress)
        for i in range(0,len(expiredNeighbors)):
            self.onAPLeft(expiredNeighbors[i], "neighbor did not send a KCM in the 3x KCM interval")
        self.processingNeighborUpdateEvent.set()

    # TODO: make me generic
    def sendCtrlToNeighbors(self, message, sub_type, key, iv, nodeID= "255.255.255.255"):
        self.processingProbeRequestEvent.wait()
        self.processingChangeKeysEvent.wait()
        self.sendingUserSpaceMessageEvent.wait()
        self.sendingUserCtrlMessageEvent.clear()
        max_ttl = 3
        msg_type = "ctrl"
        self.sendFloodingMessage(message, max_ttl, msg_type, sub_type, key, iv, nodeID)

    def sendCtrlToNeighbor(self, message, sub_type, key, iv, nodeID):
        self.sendCtrlToNeighbors(message, sub_type, key, iv, nodeID)

    def sendFlooding(self, message, maxTTL):
        self.log.debug("sendFlooding()")
        self.sendFloodingMessage(message, maxTTL)

    def sendFloodingMessage(self, message, max_ttl, msg_type='data', sub_type='std', key=str(), iv=str(), nodeID="255.255.255.255"):
        self.log.debug("sendFloodingMessage()")
        if len(key) != 16 or len(iv)!=16:
            key = self.key
            iv = self.iv
            lasthop = self.hostname
        else:
            self.log.debug("sendFloodingMessage, last hop key = old keys")
            lasthop = 'old_keys'
            #self.key_material[lasthop] = (key, iv)
            oldKeyNeighbor = Neighbor()
            oldKeyNeighbor.encryptionKey = key
            oldKeyNeighbor.encryptionIV = iv
            oldKeyNeighbor.pubKey = self.pubKey
            self.globalNeighborList[lasthop] = oldKeyNeighbor
        self.log.debug("SendFlooding to: nodeID: %s, msg_type=%s" %(nodeID, msg_type))
        #Apply asymmetric encryption for unicast messages
        if nodeID != "255.255.255.255" and msg_type=="ctrl":
            #Apply enrcyption with public key of receiver
            if nodeID in self.globalNeighborList:
                self.log.debug('Additional public key encryption for unicast CTRL message to %s applied.' % (nodeID))
                oaep = PKCS1_OAEP.new(self.globalNeighborList[nodeID].pubKey)
                asssymEncMessage = oaep.encrypt(message)
                message = asssymEncMessage
            else:
                self.log.error('Unicast Message to neighbor %s cannot be sent, neighbor is not available in neighbor list' % (nodeID))
                self.sendingUserSpaceMessageEvent.set()
                return
        elif nodeID != "255.255.255.255" and msg_type=="data":
            if nodeID in self.globalNeighborList:
                self.log.debug('Additional symmetric key encryption for unicast STD message to %s applied.' % (nodeID))
                aes = AES.new(self.globalNeighborList[nodeID].unicastSendKey, AES.MODE_CFB, self.globalNeighborList[nodeID].unicastSendIv)
                enc_message = aes.encrypt(message)
                # to base64
                enc_message_b64 = base64.encodestring(enc_message)
                message = enc_message_b64
            else:
                self.log.error('Unicast Message to neighbor %s cannot be sent, neighbor is not available in neighbor list' % (nodeID))
                self.sendingUserSpaceMessageEvent.set()
                return
        #create signature:
        sig = self.security_helper.create_signature(message, self.rsaKey)
        # encrypt message
        aes = AES.new(key, AES.MODE_CFB, iv)
        enc_message = aes.encrypt(message)
        # to base64
        enc_message_b64 = base64.encodestring(enc_message)
        if msg_type != "ctrl":
            self.log.debug('Source message: plain=%s, encrypted_B64=%s, rec:=%s' % (message, enc_message_b64, nodeID))
        json_data = { 'host': self.hostname, 'lasthop': lasthop, 'id': self.local_id, 'rec': nodeID, 'ttl': max_ttl, 'msg_type' : msg_type, 'sub_type' : sub_type, 'msg': enc_message_b64, 'sig': sig }
        self.snd_socket.send_json(json_data)
        self.local_id = self.local_id + 1

    def rxCbInternal(self, json_data):
        json_msg = json_data['msg']
        json_payload = json.loads(json_msg)
        #append additional data to application json payload, e.g. sender
        #json_payload['sender'] = json_msg['host']
        self.log.debug("####################################################")
        self.log.debug("Received message from %s Content: %s" % (str(json_data['host']), str(json_payload)))
        if json_data['host'] in self.globalNeighborList:
            self.log.debug("Lost Messages Overall: %s" % str(self.globalNeighborList[json_data['host']].rxStatsLost))
            self.log.debug("Overall Messages Received from Neighbor: %s" % str(self.globalNeighborList[json_data['host']].rxStatsSuccess))
        self.log.debug("####################################################")
        if json_payload['NS'] in self.globalAppList:
            self.log.debug("Notifying Application: %s" % str(json_payload['NS']))
            self.globalAppList[json_payload['NS']].rx_cb(json_payload)

    def sendToInternal(self, json_msg, ttl, nodeID):
        message_str = json.dumps(json_msg)
        self.processingProbeRequestEvent.wait()
        self.processingChangeKeysEvent.wait()
        self.sendingUserCtrlMessageEvent.wait()
        self.sendingUserSpaceMessageEvent.clear()
        self.sendFloodingMessage(message_str, ttl, 'data', 'std', str(), str(), nodeID)

    """
        Implementation of Northbound API
    """
    def getNeighbors(self):
        currentNeighbors = []
        for key in self.globalNeighborList:
            if self.globalNeighborList[key].ipAddress != self.hostname and self.globalNeighborList[key].ipAddress != str():
                currentNeighbors.append(self.globalNeighborList[key].ipAddress)
        return currentNeighbors

    def sendToNeighbors(self, json_msg, ttl):
        ttl = ttl + 2 # TTL of 3 equals forwarding to next neighbor
        self.sendToInternal(json_msg, ttl, "255.255.255.255")

    def sendToNeighbor(self, json_msg, nodeID):
        if nodeID in self.globalNeighborList:
            if len(self.globalNeighborList[nodeID].unicastSendKey) > 0:
                self.sendToInternal(json_msg, 3, nodeID)
                return "Success"
            else:
                self.globalNeighborList[nodeID].waitingForUnicastKeys.clear()
                max_retries = 5
                retries = 0
                while(self.globalNeighborList[nodeID].waitingForUnicastKeys.isSet() != True):
                    self.sendCtrlToNeighbor("", "ruk", str(), str(), nodeID)
                    time.sleep(0.5)
                    retries = retries + 1
                    if retries >= max_retries:
                        self.globalNeighborList[nodeID].waitingForUnicastKeys.set()
                        self.log.debug("Max retries reached, neighbor %s did not respond to request unicast key message (ruk)" % (nodeID))
                        return "Max retries reached, neighbor did not respond to request unicast key message (ruk)"
                self.log.info("New unicast keys for node %s retrieved" % (nodeID))
                self.sendToInternal(json_msg, 3, nodeID)
                self.log.debug("Mutual unicast key exchange with node %s successful" % (nodeID))
                return "Success"

        else:
            return "Unknown Neighbor"

    def registerNewApplication(self, namespace, app):
        self.globalAppList[namespace] = app

    def getResFiCredentials(self, param):
        if param == 1:
            return self.hostname
        elif param == 2:
            return self.pubKey

    def usePrivateRSAKey(self, data, mode):
        if mode == 1:
            return self.security_helper.create_signature(data, self.rsaKey)
        elif mode == 2:
            return self.security_helper.decrypt_with_private_key(self.rsaKey, data)

    def getNodeID(self):
        return self.hostname

    def setChannel(self, channel):
        freq = self.wifi_helper.translateChannelToFrequency(channel)
        if freq !=0:
            self.processingChangeKeysEvent.wait()
            self.sendingUserCtrlMessageEvent.wait()
            self.processingNeighborUpdateEvent.wait()
            #while((int(time.time()) - self.globalNeighborList[self.hostname].timestampLastKCM) < config.CHANNEL_SWITCH_GUARD) or ((int(time.time()) - self.globalNeighborList[self.hostname].timestampLastKCM) > (config.KEYCHANGEINTERVAL-config.CHANNEL_SWITCH_GUARD)):
            self.channel_switch_helper = ChannelSwitchGuardThread()
            self.channel_switch_helper.run(self.globalNeighborList[self.hostname].timestampLastKCM, config.CHANNEL_SWITCH_GUARD, config.KEYCHANGEINTERVAL, freq, channel, self.connector.setChannel, self.setChannelFinished, self.channel, self.freq)
            self.channel = channel
            self.freq = freq
            return True

        else:
            raise Exception("Unsupported Channel: " + str(channel))
            
    def setChannelFinished(self, ret, channel, freq, channelOld, freqOld):
        if ret == 'OK':
            self.channel = channel
            self.freq = freq
        else:
            self.log.warn("Channel Switch to %s not successful, returned error: %s" % (str(channel), str(ret)))  
            self.channel = channelOld
            self.freq = freqOld 

    def getChannel(self):
        return self.connector.getChannel()

    def getAvailableChannels(self, restrict5Ghz=False):
        return self.connector.getAvailableChannels(restrict5Ghz)

    def getNetworkLoad(self):
        return self.connector.getNetworkLoad()
