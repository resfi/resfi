"""
    ResFi example of a unicast sender, sends unicast messages to all 1-hop neighors
    by utilizing end-to-end encryption. The ResFi framework uses the public RSA key to
    exchange a symmetric AES session key between each neighbor and each direction.

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
from threading import Thread
from common.resfi_api import AbstractResFiApp
import random



"""
    Unicast sender /receiver example
"""
class ResFiApp(AbstractResFiApp, Thread):

    def __init__(self, log, agent):
        Thread.__init__(self)
        AbstractResFiApp.__init__(self, log, 'de.berlin.tu.tkn.unicastsender', agent)


    def run(self):
        self.log.info("%s: plugin::unicastsender started ... " % self.agent.getNodeID())

        # wait to settle down
        time.sleep(1)
        # init phase

        while not self.isTerminated():

            currentNeighbors = self.getNeighbors()
            my_msg = {}
            for i in range(len(currentNeighbors)):
                my_msg['payload'] = {'A':'B'}
                self.log.info("plugin::unicastsender sending message to: %s" % currentNeighbors[i])
                self.sendToNeighbor(my_msg, currentNeighbors[i])
            time.sleep(5)

        self.log.debug("%s: plugin::dist-chan stopped ... " % self.agent.getNodeID())

    """
    receive callback function
    """
    def rx_cb(self, json_data):
        message = json_data['payload']
        sender = json_data['originator']
        self.log.info("%s :: recv() msg from %s with payload %s" % (self.ns, sender, message))


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

