"""
    ResFi APIs:
    - NorthBoundAPI
    - SouthBoundAPI
    - Base class for all ResFi apps

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



import abc
import time
from threading import Thread


"""
Functions which can be used by application, i.e. the north-bound interface
"""
class ResFiNorthBoundAPI(object):
    __metaclass__ = abc.ABCMeta

    """
        The general northbound API
    """

    @abc.abstractmethod
    def getNeighbors(self):
        """
        List all ResFi APs in direct communication range (neighbors).
        """
        return

    @abc.abstractmethod
    def sendToNeighbor(self, message, nodeID):
        """
        Send a message to a neighboring ResFi AP identified by nodeID, messages are end-to-end encrypted using a unicast
        unidirectional symmetric AES session key. On first call, session key is transparently obtained from neighbor
        by utilizing the asymmetric RSA keys for symmetric key exchange.
        Messages are signed using the AP's private RSA key and are additionally encrypted using the group
        encryption session AES key.
        :param message: message to be sent to all direct neighbors
        :param nodeID: the unique node identifier
        """
        return

    @abc.abstractmethod
    def sendToNeighbors(self, message, ttl):
        """
        Send a message to all direct neighboring ResFi APs, messages are encrypted using the APs symmetric AES group
        encryption key and are signed using the APs private RSA key.
        :param message: message to be sent to all direct neighbors
        :param ttl: time to live value in hops
        """
        return

    @abc.abstractmethod
    def registerNewApplication(self, namespace, app):
        """
        Register a new ResFi application in the ResFi agent.
        :param namespace
        :param app object
        """
        return

    @abc.abstractmethod
    def getResFiCredentials(self, param):
        """
        Some applications are interested in getting security credentials, i.e. key material.
        :param param, param==1 returns public IP of RRMU, if param==2 returns public RSA key
        """
        return

    @abc.abstractmethod
    def usePrivateRSAKey(self, data, mode):
        """
        Used for encryption of data using the private key.
        :param data,    data to work
        :param mode     enables to utilize the private key of the RRMU. If mode == 1, returns signature computed over
                        data, if mode == 2, function decrypts data and returns plaintext.
        """
        return

    """
        The northbound RRM API
    """

    @abc.abstractmethod
    def setChannel(self, channel):
        """
        ResFi apps have the possibility to change the radio channel of the wireless interface running in AP mode.
        :param data,    channel to switch
        """
        return

    @abc.abstractmethod
    def getChannel(self, channel):
        """
        Get the current radio channel of the wireless interface running in AP mode.
        :param data,    returns currently used channel
        """
        return

    @abc.abstractmethod
    def getAvailableChannels(self):
        """
        Get a list of available radio channels for the wireless interface running in AP mode.
        """
        return

    @abc.abstractmethod
    def getNetworkLoad(self):
        """
        Get the network load currently served by this AP.
        """
        return

"""
Functions which need to be provided by the AP platform. API to be implemented by vendors as required by ResFi.
"""
class ResFiSouthBoundAPI(object):
    __metaclass__ = abc.ABCMeta

    """
        The general southbound API
    """

    @abc.abstractmethod
    def getWiredInterface(self):
        """
        Returns the wired interface aka the network interface used to connect the AP to the Internet.
        """
        return

    @abc.abstractmethod
    def subscribeToProbeRequests(self, callback):
        """
        Register a callback function to be called by the ResFi framework on the reception of a probe response frame
        :param callback, the callback to be registred.
        """
        return

    @abc.abstractmethod
    def addIEtoProbeResponses(self, pubKeyStr, SymKeyStr, SymIVStr, IpStr):
        """
        Program the information element to be transmitted in the 802.11 probe responses.
        :param pubKeyStr, hexadecimal representation of the public key encoded as string
        :param SymKeyStr, hexadecimal representation of the symmetric group encryption key encoded as string
        :param SymIVStr, hexadecimal representation of the symmetric group encryption IV encoded as string
        :param IpStr, hexadecimal representation of the public IP address of the AP's RRMU encoded as string
        """
        return

    @abc.abstractmethod
    def performActiveScan(self, fullScan, ssid, freq, pubKeyStr, SymKeyStr, SymIVStr, IpStr):
        """
        Perform an active scan using the wireless interface.
        :param fullScan,    whether to perform a full scan or not
        :param ssid, whether to scan for a particular SSID
        :param freq, whether to scan on just the given frequency
        :param pubKeyStr, hexadecimal representation of the public key encoded as string
        :param SymKeyStr, hexadecimal representation of the symmetric group encryption key encoded as string
        :param SymIVStr, hexadecimal representation of the symmetric group encryption IV encoded as string
        :param IpStr, hexadecimal representation of the public IP address of the AP's RRMU encoded as string
        """
        return

    """
        The southbound RRM API
    """

    @abc.abstractmethod
    def getInfoOfAssociatedSTAs(self):
        """
        Get information about associated STAs served by wireless interface running in AP mode.
        """
        return

    @abc.abstractmethod
    def setChannel(self, channel):
        """
        Setting the radio channel to be used by wireless interface running in AP mode.
        :param data,    channel to switch
        """
        return

    @abc.abstractmethod
    def getChannel(self):
        """
        Getting the radio channel used by wireless interface running in AP mode.
        :param data,    returns currently used channel
        """
        return

"""
Base class for all ResFi apps. Each app needs to derive from this class.
"""
class AbstractResFiApp(ResFiNorthBoundAPI, Thread):
    __metaclass__ = abc.ABCMeta

    def __init__(self, log, ns, agent):
        Thread.__init__(self)
        self.log = log
        self.ns = ns
        self.agent = agent
        self.toTeriminate = False
        self.registerNewApplication(self.ns, self)

    @abc.abstractmethod
    def run(self):
        return

    # receive callback function
    @abc.abstractmethod
    def rx_cb(self, json_data):
        return

    @abc.abstractmethod
    def newLink_cb(self, nodeID):
        return

    @abc.abstractmethod
    def linkFailure_cb(self, nodeID):
        return

    def terminate(self):
        self.toTeriminate = True

    def isTerminated(self):
        return self.toTeriminate

    def ns_decorator(func):
        def wrapper(self, *args, **kwargs):
            # add resfi app namespace
            args[0]['NS'] = self.ns
            args[0]['originator'] = self.agent.getNodeID()
            args[0]['tx_time_mus'] = long(time.time()*1000000) # timestamp in micros
            # TODO: add even more stuff here
            return func(self, *args, **kwargs)
        return wrapper

    """
    Delegator
    """
    def getNeighbors(self):
        return self.agent.getNeighbors()

    @ns_decorator
    def sendToNeighbors(self, message, ttl):
        return self.agent.sendToNeighbors(message, ttl)

    @ns_decorator
    def sendToNeighbor(self, message, nodeID):
        return self.agent.sendToNeighbor(message, nodeID)

    def registerNewApplication(self, namespace, app):
        return self.agent.registerNewApplication(namespace, app)

    def getResFiCredentials(self, param):
        return self.agent.getResFiCredentials(param)

    def usePrivateRSAKey(self, data, mode):
        return self.agent.usePrivateRSAKey(data, mode)

    def setChannel(self, channel):
        return self.agent.setChannel(channel)

    def getChannel(self):
        return self.agent.getChannel()

    def getAvailableChannels(self, restrict5Ghz=False):
        return self.agent.getAvailableChannels(restrict5Ghz)

    def getNetworkLoad(self):
        return self.agent.getNetworkLoad()
