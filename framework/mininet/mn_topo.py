#!/usr/bin/env python


'''
    Create topology in Mininet

    This software uses parts of the data from SamKnows measurement campaign. For details see
    https://www.fcc.gov/measuring-broadband-america/2014/validated-data-fixed-2014
    File in use is from the campaign is curr_udplatency.csv, whereas only the values (rtt_avg, successes, failures)
    are preserved in curr_udplatency_shorted.csv

        Copyright (C) 2015 Sven Zehl, Anatolij Zubow, Michael Doering, Adam Wolisz

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

'''

__author__ = 'zehl, zubow, wolisz, doering'

from mininet.topo import Topo
from random import randint, choice, seed
import os, math

DEBUG = 1

class MnTopo(Topo):
    def __init__(self, depth, uMin, uMax, seeding, **opts):
        Topo.__init__(self, **opts)
        if not seeding == 0:
            seed(seeding)

        self.hostNum = 0
        self.switchNum = 1
        self.uMin = uMin
        self.uMax = uMax
        self.defaultWirelessRate = 6 # [Mbps]
        self.defaultWirelessLoss = 0 #  [percentage]
        self.defaultWirelessDelay = 2 # [ms]
        self.defaultWirelessQueue = 50 # [packets]

        self.bachhaulQueueLength = 50
        self.backhaulSwitch = self.addSwitch( 'bsw0' )
        if depth == 1:
            self.gswitch = self.addSwitch('gsw%s' % self.switchNum)
        self.f = open('measurements/apLinkData.csv','wb')
        self.overallLinkBandwith = 0
        # Build topology
        self.addTree( depth, uMin, uMax, 0, None )
        self.f.close()
        assert self.overallLinkBandwith < 1000, "Overall backhaul bandwith must be lower than 1Gbps!"


    ''' Get backhaul data from file
    '''
    def getLinkData(self):
        if os.path.isfile('traces/curr_udplatency_shorted.csv'):
            lines = open('traces/curr_udplatency_shorted.csv').read().splitlines()
            cline = choice(lines).strip().split(",")
            # (rtt_avg, successes, failures)
            latency = int(math.floor(float(cline[0])/2/1000))
            loss = float(cline[2])/(float(cline[1])+float(cline[2]))
            # use fixed rates for DSL
            rates = [3, 6, 12, 24, 42.88]
            rate = rates[randint(0,len(rates)-1)]
        else:
            assert False, "File 'traces/curr_udplatency_shorted.csv' does not exist!"
        return [rate, latency, loss]


    ''' Build topology
    '''
    def addTree(self, maxDepth, fanOutMin, fanOutMax, n, parent):

        node = self.addHost( 'ap%s' % self.hostNum )
        # maxDepth of one leads to star topology
        if maxDepth == 1:
            self.addLink( node, self.gswitch, bw=self.defaultWirelessRate, delay=str(self.defaultWirelessDelay)+'ms',
                          loss=self.defaultWirelessLoss, max_queue_size=self.defaultWirelessQueue, use_htb=True )
        if not self.hostNum == 0:
            backHaul=self.getLinkData()
            if DEBUG:
                print ("Backhaul links - AP%s, rate: %s, latency: %s, loss: %s" % (self.hostNum, backHaul[0], backHaul[1], backHaul[2]))
            #(Mbps, latency ms)
            self.f.write(str(backHaul[0]) + "," + str(backHaul[1]) + "\n")
            self.overallLinkBandwith += float(backHaul[0])
            self.addLink(node, self.backhaulSwitch, bw=backHaul[0], delay=str(backHaul[1])+'ms',loss=backHaul[2],
                         max_queue_size=self.bachhaulQueueLength, use_htb=True)
        else:
            self.addLink(node, self.backhaulSwitch, bw=1000, delay='0ms',loss=0,
                         max_queue_size=self.bachhaulQueueLength, use_htb=True)
        self.hostNum += 1

        if n == maxDepth:
            return node

        fanOut = randint(fanOutMin, fanOutMax)

        # special use-case
        if parent is None:
            for i in range(fanOut):
                self.addTree(maxDepth, fanOutMin, fanOutMax, n+1, node)
        else:
            # inner node
            helpLst = []
            for _ in range(fanOut):
                child = self.addTree(maxDepth, fanOutMin, fanOutMax, n+1, node)
                helpLst.append(child)

            switch = self.addSwitch( 'gsw%s' % self.switchNum )
            self.addLink( parent, switch, bw=self.defaultWirelessRate, delay=str(self.defaultWirelessDelay)+'ms',
                          loss=self.defaultWirelessLoss, max_queue_size=self.defaultWirelessQueue, use_htb=True )
            self.addLink( node, switch, bw=self.defaultWirelessRate, delay=str(self.defaultWirelessDelay)+'ms',
                          loss=self.defaultWirelessLoss, max_queue_size=self.defaultWirelessQueue, use_htb=True )
            for childx in helpLst:
                self.addLink( childx, switch, bw=self.defaultWirelessRate, delay=str(self.defaultWirelessDelay)+'ms',
                              loss=self.defaultWirelessLoss, max_queue_size=self.defaultWirelessQueue, use_htb=True )
            self.switchNum += 1

        return node
