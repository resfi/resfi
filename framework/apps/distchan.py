"""
    Distributed channel assignment algorithm as example application.

    See paper for details of the algorithm:
    Mishra, Arunesh, Suman Banerjee, and William Arbaugh.
    "Weighted coloring based channel assignment for WLANs."
    ACM SIGMOBILE Mobile Computing and Communications Review 9.3 (2005): 19-31.

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

import time
from common.resfi_api import AbstractResFiApp
import random
import thread
import zmq
import sys
import json

class ResFiApp(AbstractResFiApp):

    def __init__(self, log, agent):
        AbstractResFiApp.__init__(self, log, 'de.berlin.tu.tkn.distchan', agent)
        # channel change interval
        self.jitter = 10
        self.min_load = 1
        self.start_ts = long(time.time() * 1000000)
        self.Hc = {}
        self.Mc = {}
        self.Sc = {}
        self.aps = {}
        self.nbMap = {} 
        self.lneigh = {}
        self.load = 0.0
        self.ch_lst = []
        self.used_ch_lst = {}
        self.rxcntr = 0
        self.sniffer_port = "9999"
        self.nrf_load = {}
        self.nrf_freq = {}
        self.sniffer_context = zmq.Context()
        self.sniffer_socket = self.sniffer_context.socket(zmq.REQ)
        self.sniffer_socket.connect ("tcp://localhost:%s" % self.sniffer_port)
        self.loadInformationTimeout = 30000 #in ms
        self.leastLoadMemory = {}
        self.last_channel_switch_time = 0
        self.chaSwitchGuardTimeLoWLoadChange = 30000 # in ms
        #self.available_ch_lst = self.getAvailableChannels(True)
        self.available_ch_lst = []
        #self.available_ch_lst.append(36)
        self.available_ch_lst.append(48)
        self.available_ch_lst.append(1)
        self.available_ch_lst.append(6)
        self.available_ch_lst.append(10)
        self.ch_lst = self.available_ch_lst
        self.log.info("%.2f: (%s): plugin:: dist-chan available channels = %s " % (self.getRelativeTs(), self.agent.getNodeID(), str(self.available_ch_lst)))				
        self.my_rf_channel = self.getChannel()
        self.log.info("%.2f: (%s): plugin:: dist-chan curr ch=%d" % (self.getRelativeTs(), self.agent.getNodeID(), self.my_rf_channel))


    def getRelativeTs(self):
        timestamp = long(time.time() * 1000000) # timestamp in micros
        rel_ts = (timestamp - self.start_ts)
        return rel_ts

    def run(self):

        self.log.debug("%s: plugin::dist-chan started ... " % self.agent.getNodeID())

        # wait to settle down
        time.sleep(5)
        # init phase

        # wait random to make sure all nodes are not synchronized
        rnd_wait_time = random.uniform(0, self.jitter)
        time.sleep(rnd_wait_time)

        while not self.isTerminated():

            self.my_rf_channel = self.getChannel()
            self.log.info("%.2f: (%s): plugin:: dist-chan (curr neighbors: %d) curr ch=%d, free channels:%s " % (self.getRelativeTs(), self.agent.getNodeID(), len(self.getNeighbors()), self.my_rf_channel, str(self.ch_lst)))

            self.load = max(self.min_load, self.getNetworkLoad())
            self.log.debug('Own Load is %0.2f' % self.load)
            self.sniffer_socket.send("Give me the resuls")
            message_sniffer = self.sniffer_socket.recv()
            nrf_aps = json.loads(message_sniffer)
            self.nrf_load = {}
            self.nrf_freq = {}
            for ap in nrf_aps:
                for sta in nrf_aps[ap]:
                    if sta == "activeStas":# and len(aps[ap][sta]) > 0:
                        #print "AP: "+str(ap) + " STAs: " +str(aps[ap][sta]) + " Load: "+str(len(aps[ap][sta]))
                        self.nrf_load[str(ap)] = len(nrf_aps[ap][sta])
                        self.nrf_freq[str(ap)] = nrf_aps[ap]['freq']
            my_msg = {}
            my_msg['payload'] = {'ch' : self.my_rf_channel, 'load' : self.load, 'bssid' : self.getBssid(), 'type' : 'rf', 'detector' : self.agent.getNodeID()}
            self.sendToNeighbors(my_msg, 1)
            for ap in self.nrf_load:
                if str(self.getBssid()) != str(ap):
                    nrf_channel = self.agent.wifi_helper.translateFrequencyToChannel(int(self.nrf_freq[str(ap)]))
                    nrf_load = float(self.nrf_load[str(ap)])
                    nrf_bssid = str(ap)
                    nrf_type = 'nrf'
                    my_msg = {}
                    my_msg['payload'] = {'ch' : nrf_channel, 'load' : nrf_load, 'bssid' : nrf_bssid, 'type' : nrf_type, 'detector' : self.agent.getNodeID()}
                    
                    #policy for handling information about the same ap on the same channel
                    if nrf_bssid in self.nbMap and self.nbMap[nrf_bssid]['ch'] == nrf_channel:
                        if int(round(time.time() * 1000)) - self.nbMap[nrf_bssid]['last_refresh'] > self.loadInformationTimeout: #30sec timeout for values regardless who was detector or which type
                            # save last update dont care who is the detector
                            self.nbMap[nrf_bssid] = {'load': nrf_load, 'ch': nrf_channel, 'type': nrf_type, 'detector' : self.agent.getNodeID(), 'last_refresh' : int(round(time.time() * 1000))}
                        elif self.nbMap[nrf_bssid]['type'] == 'rf' and nrf_type == 'nrf': #leave the rf value dont care about the estimated value
                            pass    
                        elif self.nbMap[nrf_bssid]['detector'] == self.agent.getNodeID(): # if it is just an update from the original detector, update own neighbor db       
                            self.nbMap[nrf_bssid] = {'load': nrf_load, 'ch': nrf_channel, 'type': nrf_type, 'detector' : self.agent.getNodeID(), 'last_refresh' : int(round(time.time() * 1000))}
                        elif self.nbMap[nrf_bssid]['detector'] != self.agent.getNodeID(): #if I have new information from different detector, take the worst case assumption
                            if self.nbMap[nrf_bssid]['load'] > nrf_load:
                                pass
                            else:        
                                self.nbMap[nrf_bssid] = {'load': nrf_load, 'ch': nrf_channel, 'type': nrf_type, 'detector' : self.agent.getNodeID(), 'last_refresh' : int(round(time.time() * 1000))}
                    else:
                        self.nbMap[nrf_bssid] = {'load': nrf_load, 'ch': nrf_channel, 'type': nrf_type, 'detector' : self.agent.getNodeID(), 'last_refresh' : int(round(time.time() * 1000))}
                    
                    #self.nbMap[nrf_bssid] = {'load': nrf_load, 'ch': nrf_channel, 'type': nrf_type, 'detector' : self.agent.getNodeID(), 'last_refresh' : int(round(time.time() * 1000))}
                    self.sendToNeighbors(my_msg, 1)
            #Filter out outdated entries    
            outdatedList = []
            for entry in self.nbMap: # for each entry
                if int(round(time.time() * 1000)) - self.nbMap[entry]['last_refresh'] > self.loadInformationTimeout:
                    outdatedList.append(entry)
            for oldEntry in outdatedList:      
                del self.nbMap[oldEntry]
            # random backoff
            rnd_wait_time = random.uniform(0, self.jitter/2)
            time.sleep(rnd_wait_time)

        self.log.debug("%s: plugin::dist-chan stopped ... " % self.agent.getNodeID())
        
        					
            
    """
    receive callback function
    """
    def rx_cb(self, json_data):
        self.log.info("%s :: recv() msg from %s at %d: %s" % (self.ns, json_data['originator'], json_data['tx_time_mus'], json_data))

        message = json_data['payload']

        #self.updateChannelList()

        timestampSent = json_data['tx_time_mus']
        sender = json_data['originator']
        nb_channel = int(message['ch'])
        nb_load = float(message['load'])
        nb_bssid = message['bssid']
        nb_type = message['type'] #rf or nrf
        nb_detector = message['detector']
        
        #policy for handling information about the same ap on the same channel
        if nb_bssid in self.nbMap and self.nbMap[nb_bssid]['ch'] == nb_channel:
            if int(round(time.time() * 1000)) - self.nbMap[nb_bssid]['last_refresh'] > self.loadInformationTimeout: #30sec timeout for values regardless who was detector or which type
                # save last update dont care who is the detector
                self.nbMap[nb_bssid] = {'load': nb_load, 'ch': nb_channel, 'type': nb_type, 'detector' : nb_detector, 'last_refresh' : int(round(time.time() * 1000))}
            elif self.nbMap[nb_bssid]['type'] == 'nrf' and nb_type == 'rf': # if the new measurement is rf and the old nrf overwrite it
                self.nbMap[nb_bssid] = {'load': nb_load, 'ch': nb_channel, 'type': nb_type, 'detector' : nb_detector, 'last_refresh' : int(round(time.time() * 1000))}
            elif self.nbMap[nb_bssid]['type'] == 'rf' and nb_type == 'nrf': #leave the rf value dont care about the estimated value
                pass    
            elif self.nbMap[nb_bssid]['detector'] == nb_detector: # if it is just an update from the original detector, update own neighbor db       
                self.nbMap[nb_bssid] = {'load': nb_load, 'ch': nb_channel, 'type': nb_type, 'detector' : nb_detector, 'last_refresh' : int(round(time.time() * 1000))}
            elif self.nbMap[nb_bssid]['detector'] != nb_detector: #if I have new information from different detector, take the worst case assumption
                if self.nbMap[nb_bssid]['load'] >= nb_load:
                    pass
                else:        
                    self.nbMap[nb_bssid] = {'load': nb_load, 'ch': nb_channel, 'type': nb_type, 'detector' : nb_detector, 'last_refresh' : int(round(time.time() * 1000))}
        else:
            self.nbMap[nb_bssid] = {'load': nb_load, 'ch': nb_channel, 'type': nb_type, 'detector' : nb_detector, 'last_refresh' : int(round(time.time() * 1000))}
        
        print "##### Neighbor MAP ######"
        print self.nbMap
        print '#########################' 
        self.log.debug("%.2f: (%s): plugin:: dist-chan received from %s info: [%s](%s): %s/%s"
                       % (self.getRelativeTs(), self.agent.getNodeID(), sender, str(nb_bssid), str(nb_type), str(nb_channel), str(nb_load)))
        lsumcha = {}
        for ch in self.ch_lst: # for each channel
            lsumcha[str(ch)] = 0.0 # reset to zero
            lsumcha[str(ch)] = lsumcha[str(ch)] + self.load 
            for entry in self.nbMap: # for each neighbor
                nbCh = self.nbMap[entry]['ch']
                if nbCh == ch: # same channel
                    lsumcha[str(ch)] = lsumcha[str(ch)] + self.nbMap[entry]['load']
                   
        bestcha = 0
        leastload = 1e9
        print "XXXXXXXX CHANNEL LOAD XXXXXXXXXX"
        for ch in self.ch_lst: # for each channel
                        print"Channel: "+str(ch)+"\t Load: "+str(lsumcha[str(ch)])
			if lsumcha[str(ch)] < leastload:
				bestcha = ch
				leastload = lsumcha[str(ch)]

        # the best channel to be used
        self.my_rf_channel = self.getChannel()
        print "Best Channel: "+str(bestcha)
        print "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        #Check how big the load difference on the channel is in comparison to the last time we used this channel
        if str(bestcha) in self.leastLoadMemory and str(self.my_rf_channel) in self.leastLoadMemory and bestcha is not 0 and self.my_rf_channel != bestcha:
            time_now = int(round(time.time() * 1000))
            load_diff_bc = abs(self.leastLoadMemory[str(bestcha)]-leastload) #load difference of new best channel between the load the channel had when we lastly switched to that channel to now
            load_diff_cc = abs(self.leastLoadMemory[str(self.my_rf_channel)]-lsumcha[str(self.my_rf_channel)]) #load difference between the load of the current channel from last channel switch to load now on the channel
            time_diff_ls = time_now - self.last_channel_switch_time # time difference last channel switch in ms
            if ((load_diff_bc <= 1.0) or (load_diff_cc <= 1.0 )) and (time_diff_ls < self.chaSwitchGuardTimeLoWLoadChange): 
                #if load difference is smaller or equal 1 (of the currently used channel or the channel we want to switch to) 
                #and the channel was switched lastly, dont switch the channel.
                print "!!!Channel Switch stopped by Oscilation Protection Mechanism!!!"
                print "Duration till channel was switched lastly: "+str(time_now - self.last_channel_switch_time)+"ms ,"
                print "load difference of best channel: \t"+str(load_diff_bc)+", "
                print "load difference of currently used channel: \t"+str(load_diff_cc)+"."
                return
        
        if bestcha is not 0 and self.my_rf_channel != bestcha:
            self.log.info("(%s): plugin:: dist-chan chanel switch from %s to %s"
                           % (self.agent.getNodeID(), str(self.my_rf_channel), str(bestcha)))
            self.setChannel(bestcha)
            self.my_rf_channel = self.getChannel()
            #Save last least load of channel in memory for oscilation avoidance
            self.leastLoadMemory[str(bestcha)]=leastload
            self.last_channel_switch_time = int(round(time.time() * 1000))


    """
    new Link Notification Callback
    """
    def newLink_cb(self, nodeID):
        self.log.info("%s ::newLink_cb() new AP neighbor detected notification (newLink: %s)" % (self.ns, nodeID))

    """
    Link Lost Notification Callback
    """
    def linkFailure_cb(self, nodeID):
        self.log.info("%s :: linkFailure_cb() neighbor AP disconnected (lostLink: %s)" % (self.ns, nodeID))

