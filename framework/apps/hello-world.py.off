"""
    Hello World message sender as example application 
    for the ResFi framework.

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

class ResFiApp(AbstractResFiApp):

    def __init__(self, log, agent):
        AbstractResFiApp.__init__(self, log, "de.berlin.tu.tkn.hello-world", agent)

    """
    Function will be started by ResFi runtime
    """
    def run(self):
        self.log.debug("%s: plugin::hello-world started ... " % self.agent.getNodeID())

        # control loop
        while not self.isTerminated():

            # send message to ResFi neighbors using ResFi northbound API
            my_msg = {}
            my_msg['payload'] = {'msg1' : 'hello', 'msg2' : 'world!'}
            self.log.info("%s: plugin::hello-world sending %s to all one hop neighbors ... " 
                % (self.agent.getNodeID(), str(my_msg)))
            self.sendToNeighbors(my_msg, 1)

            time.sleep(1)

        self.log.debug("%s: plugin::hello-world stopped ... " % self.agent.getNodeID())

    """
    receive callback function
    """
    def rx_cb(self, json_data):
        self.log.info("%s :: recv() msg from %s at %d: %s" % (self.ns, json_data['originator'], 
            json_data['tx_time_mus'], json_data))

    """
    new Link Notification Callback
    """
    def newLink_cb(self, nodeID):
        self.log.info("%s ::newLink_cb() new AP neighbor detected notification (newLink: %s)" 
            % (self.ns, nodeID))

    """
    Link Lost Notification Callback
    """
    def linkFailure_cb(self, nodeID):
        self.log.info("%s :: linkFailure_cb() neighbor AP disconnected (lostLink: %s)" 
            % (self.ns, nodeID))
