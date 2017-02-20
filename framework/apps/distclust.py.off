'''
Distributed and Mobility-Adaptive Clustering Algorithm (DMAC) as example application.

See paper for details of the algorithm:
Basagni, Stefano. "Distributed clustering for ad hoc networks." Parallel Architectures,
Algorithms, and Networks, 1999. (I-SPAN'99) Proceedings. Fourth InternationalSymposium on. IEEE, 1999.

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
'''

import time
from common.resfi_api import AbstractResFiApp
import random

__author__ = 'zubow'

# command types
class MsgCommands:
    SEND_CH = 1 # send cluster head message
    JOIN = 2 # send join message


class ResFiApp(AbstractResFiApp):

    def __init__(self, log, agent):
        AbstractResFiApp.__init__(self, log, 'de.berlin.tu.tkn.distclust', agent)

        self.log = log
        # my own ID
        self.v = self.agent.getNodeID()
        # my own weight
        self.w = self.getNetworkLoad()
        #  variable in which every node records the (ID of the) clusterhead that it joins.
        self.clusterHead = -1
        self.clusterHeadW = -1
        # the set of nodes in vs cluster. It is initialized to null , and it is updated only if v is a clusterhead
        self.cluster = []
        # boolean variables
        self.ch = {self.v: False}
        self.join = {self.v: False}
        # save weights
        self.warr = {self.v: self.w}
        # testing
        self.jitter = 10


    """ Link Lost Notification Callback """
    def linkFailure_cb(self, u):
        del self.ch[u]
        del self.warr[u]
        self.log.info('%s: link_failure to %s' % (self.v, u))
        if self.ch[self.v] and u in self.cluster:
            self.cluster = [x for x in self.cluster if x != u]
        elif self.clusterHead == u:
            self.init()


    """ new Link Notification Callback """
    def newLink_cb(self, nodeID):
        self.log.info("%s ::newLink_cb() new AP neighbor detected notification (newLink: %s)" % (self.ns, nodeID))
        # inform my neighbors about my state
        self.init()


    def getNodeId(self):
        return self.nodeId


    def init(self):
        self.log.info('%s: init' % self.v)
        (n_max, w_m) = self.chooseClusterHead()
        if n_max == None:
            self.ch[self.v] = True
            self.clusterHead = self.v
            self.clusterHeadW = self.w
            self.cluster = []
            self.cluster.append(self.v)
            self.sendCh()
        else:
            self.clusterHead = n_max
            self.clusterHeadW = w_m
            self.cluster = []
            self.sendJoin(n_max)


    def chooseClusterHead(self):
        (n_m, w_m) = (None, -1)

        for idX in self.ch: # for each neighbor
            isChX = self.ch[idX]
            wX = self.warr[idX]
            if isChX and (wX > w_m or (wX == w_m and idX > n_m)):
                (n_m, w_m) = (idX, wX)
        return (n_m, w_m)


    def recvCh(self, u, wu):
        self.ch[u] = True # azu
        self.warr[u] = wu
        self.log.info('%s: recvCh via ResFI API' % self.v)
        if wu > self.clusterHeadW:
            self.sendJoin(wu) # AZU: before: u
            self.clusterHead = u
            if self.ch[self.v]:
                self.ch[self.v] = False


    def recvJoin(self, u, z):
        self.join[u] = True # azu
        self.log.info('%s: recvJoin via ResFI API %s->%s' % (self.v, u, z))
        if self.ch[self.v]:
            if z == self.v:
                self.cluster.append(u)
            else:
                self.cluster = [x for x in self.cluster if x != u]
        elif self.clusterHead == u:
            self.init()


    def sendCh(self):
        self.ch[self.v] = True # azu
        self.log.info('%s: sendCh to neighbors' % self.v)

        timestamp = long(time.time() * 1000000) # timestamp in micros

        msg = {}
        msg['originator'] = self.v
        msg['timestamp'] = timestamp
        msg['cmd'] = MsgCommands.SEND_CH
        msg['payload'] = {'load' : self.w}

        self.sendToNeighbors(msg, 1)


    def sendJoin(self, n_max):
        self.log.info('%s: sendJoin to %s' % (self.v, n_max))

        timestamp = long(time.time() * 1000000) # timestamp in micros

        msg = {}
        msg['originator'] = self.v
        msg['timestamp'] = timestamp
        msg['cmd'] = MsgCommands.JOIN
        msg['payload'] = {'n_max' : n_max}

        self.sendToNeighbors(msg, 1)


    def rx_cb(self, msg):
        """ receive callback function """
        self.log.info('%s: rx_cb from neighbor' % self.v)

        op = msg['cmd']

        if op ==MsgCommands.SEND_CH:
            u = msg['originator']
            wu = msg['payload']['load']
            self.recvCh(u, float(wu))
        elif op == MsgCommands.JOIN:
            u = msg['originator']
            z = msg['payload']['n_max']
            self.recvJoin(u, z)


    def toString(self):
        self.log.info('node: %s, load: %.2f, head=%s' % (self.v, self.w, self.clusterHead))


    def run(self):

        # wait to settle down
        time.sleep(5)

        # wait random to make sure all nodes are not synchronized
        rnd_wait_time = random.uniform(0, self.jitter)
        time.sleep(rnd_wait_time)

        while not self.isTerminated():
            self.log.info('run() ... check load ...')

            self.log.info("%s: plugin:: dist-chan (curr neighbors: %d)" % (self.agent.getNodeID(), len(self.getNeighbors())))

            #if self.w != self.getNetworkLoad():
            # update load
            self.w = self.getNetworkLoad()
            # inform neighbors about my new network load
            self.init()

            # random backoff
            rnd_wait_time = random.uniform(0, self.jitter/2)
            time.sleep(rnd_wait_time)

            # print out current clustering
            self.toString()
