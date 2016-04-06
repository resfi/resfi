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


class ResFiApp(AbstractResFiApp):

    def __init__(self, log, agent):
        AbstractResFiApp.__init__(self, log, 'de.berlin.tu.tkn.distchan', agent)
        # channel change interval
        self.jitter = 10
        self.min_load = 0.5
        self.start_ts = long(time.time() * 1000000)
        self.Hc = {}
        self.nbMap = {}
        self.ch_lst = self.getAvailableChannels(True)
        self.log.info("%.2f: (%s): plugin:: dist-chan available channels = %s " % (self.getRelativeTs(), self.agent.getNodeID(), str(self.ch_lst)))
        self.my_rf_channel = self.getChannel()
        self.log.info("%.2f: (%s): plugin:: dist-chan curr ch=%d" % (self.getRelativeTs(), self.agent.getNodeID(), self.my_rf_channel))

    def getRelativeTs(self):
        timestamp = long(time.time() * 1000000) # timestamp in micros
        rel_ts = (timestamp - self.start_ts)
        return rel_ts

    def run(self):

        #return

        self.log.debug("%s: plugin::dist-chan started ... " % self.agent.getNodeID())

        # wait to settle down
        time.sleep(5)
        # init phase

        for ii in range(len(self.ch_lst)):
            self.Hc[ii] = 0

        # wait random to make sure all nodes are not synchronized
        rnd_wait_time = random.uniform(0, self.jitter)
        time.sleep(rnd_wait_time)

        while not self.isTerminated():

            self.my_rf_channel = self.getChannel()
            self.log.info("%.2f: (%s): plugin:: dist-chan (curr neighbors: %d) curr ch=%d" % (self.getRelativeTs(), self.agent.getNodeID(), len(self.getNeighbors()), self.my_rf_channel))

            load = max(self.min_load, self.getNetworkLoad())
            self.log.debug('Load is %0.2f' % load)

            my_msg = {}
            my_msg['payload'] = {'ch' : self.my_rf_channel, 'load' : load}
            self.sendToNeighbors(my_msg, 1)

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

        timestampSent = json_data['tx_time_mus']
        sender = json_data['originator']
        nb_channel = int(message['ch'])
        nb_load = float(message['load'])

        # save last update of each node
        self.nbMap[sender] = {'load': nb_load, 'ch': nb_channel}

        self.log.debug("%.2f: (%s): plugin:: dist-chan received from %s info: %s/%s"
                       % (self.getRelativeTs(), self.agent.getNodeID(), sender, str(nb_channel), str(nb_load)))

        # OPT phase
        for entry in self.nbMap:
            # for each neighbor
            tmpCh = self.nbMap[entry]['ch']
            tmpLoad = self.nbMap[entry]['load']

            self.log.debug('NB info: %s -> (c=%s,l=%s)' % (entry, str(tmpCh), str(tmpLoad)))

        my_load = max(self.min_load, self.getNetworkLoad())

        self.log.debug('Load is %0.2f' % my_load)

        # calc Hc as proposed in Hminmax algorithm:
        for ii in range(len(self.ch_lst)): # for each channel
            self.Hc[ii] = 0 # reset to zero
            for entry in self.nbMap: # for each neighbor
                tmpCh = self.nbMap[entry]['ch']
                if tmpCh == self.ch_lst[ii]: # same channel
                    # select the max() weight; here load
                    self.Hc[ii] = max(self.Hc[ii], my_load + self.nbMap[entry]['load'])

        # choose min
        best_k = -1
        best_val = 1e3
        for ii in range(len(self.ch_lst)):
            self.log.debug('NB: max weight on ch=%d -> %0.2f' % (self.ch_lst[ii], self.Hc[ii]))

            if self.Hc[ii] < best_val:
                best_k = ii
                best_val = self.Hc[ii]

        # the best channel to be used
        self.my_rf_channel = self.getChannel()

        new_channel = self.ch_lst[best_k]
        if self.my_rf_channel != new_channel:
            #self.agent.wifi_helper.translateFrequencyToChannel(int(ch_lst[0]))
            self.log.info("%.2f: (%s): plugin:: dist-chan chanel switch from %s to %s"
                           % (self.getRelativeTs(), self.agent.getNodeID(), str(self.my_rf_channel), str(new_channel)))
            self.setChannel(new_channel)
            self.my_rf_channel = self.getChannel()


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
