#!/usr/bin/env python

'''
    Mininet driver for ResFi.


    sudo python mn_driver.py


    Data from SamKnows measurement campaign: https://www.fcc.gov/measuring-broadband-america/2014/validated-data-fixed-2014
    File in use is curr_udplatency_shorted.csv, with field stripped to (rtt_avg, successes, failures)

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

from mininet.net import Mininet
from mininet.link import TCLink
from mininet.node import Controller
from mininet.cli import CLI
import re, math, time

from mn_topo import MnTopo
import os, time, datetime

from mininet.node import OVSController


import argparse


__author__ = 'zehl, zubow, wolisz, doering'

def main(logFile, depth, uMin, uMax, runtime, seeding, cli):

    # create residential WiFi topology
    mytopo = MnTopo(depth, uMin, uMax, seeding)

    # create & start Mininet
    net = Mininet(topo=mytopo, controller=None, link=TCLink, autoStaticArp=True)
    net.addController(Controller('c0'))
    net.start()
    # assign IP addresses to interfaces
    linklist = mytopo.links(sort=True)
    linklist.reverse()

    idx = 1
    while linklist:
        item = linklist.pop()
        if re.match("gsw\d", item[1]):
            apid = re.findall(r'\d+',item[0])[0]
            swid = str(int(re.findall(r'\d+',item[1])[0]))
            net.getNodeByName(item[0]).setIP("192.168.%s.%s/24" % (swid, str(int(apid)+1)), intf="ap%s-eth%s" % (apid, idx))
            idx += 1
        else:
            idx = 1

    if cli == 1:
        CLI( net )
    time.sleep(10)
    nodelist = mytopo.nodes(sort=True)
    no_nodes = 0
    while nodelist:
        item = nodelist.pop()
        if re.match("ap\d", item):
            with open("measurements/stdout" + item + ".txt","wb") as out, open("measurements/stderr" + item + ".txt","wb") as err:
                time.sleep(5)
                net.getNodeByName(item).popen("python ../resfi_loader.py -r %s" % runtime, stdout=out, stderr=err)
                no_nodes = no_nodes + 1

    print "script running. please wait."

    # wait until end time is reached
    start = datetime.datetime.now()
    while True:
        now = datetime.datetime.now()
        if (now - start).seconds < runtime:
            time.sleep(0.5)
        else:
            break

    net.stop()


# main entry point
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Process commandline options.')
    parser.add_argument('-r', '--runtime', default=200, type=int,
        help='Emulation runtime')
    parser.add_argument('-s', '--seed', default=0, type=int,
        help='Seed')
    parser.add_argument('-t', '--topo', default='star',
        help='Choose topology: star, tree')
    parser.add_argument('-n', '--nodes', default=15, type=int,
        help='Maximum number of nodes')
    parser.add_argument('-c', '--cli', default=0, type=int,
        help='Open Mininet CLI for manual simulation (1) or start automatic (0) (default)')

    print ''' ResFi Copyright (C) 2015 Sven Zehl, Anatolij Zubow, Michael Doering
    This program comes with ABSOLUTELY NO WARRANTY.
    This is free software, and you are welcome to redistribute it
    under certain conditions.
    '''

    results = parser.parse_args()
    runtime = results.runtime

    if results.seed == 0:
        fseed=int(time.time())
    else:
        fseed=results.seed

    if results.cli == 1:
        cli =1
    else:
        cli = 0

    # topology configuration
    if results.topo == "star":
        depth = 1
        uMin = 2
        uMax = results.nodes
    elif results.topo == "tree":
        depth = 3
        uMin = 1
        uMax = math.ceil(math.log(results.nodes,2))-1

    if not os.path.exists("measurements"):
        os.makedirs("measurements")
    logFile = open('measurements/log.txt','a')

    # start mininet
    main(logFile, depth=depth, uMin=uMin, uMax=uMax, runtime=runtime, seeding=fseed, cli=cli)

    logFile.close()
