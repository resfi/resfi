# ResFi: A Secure Framework for Distributed Radio Resource Management of Residential WiFi Networks 

## 0. What is ResFi?
In dense deployments of residential WiFi networks individual users suffer performance degradation due to both contention and interference.
While Radio Resource Management (RRM) is known to mitigate this effects its application in residential WiFi networks being by nature unplanned 
and individually managed creates a big challenge.
We propose ResFi - a framework supporting creation of RRM functionality in legacy deployments.
The radio interfaces are used for efficient discovery of adjacent APs and as a side-channel to establish a secure communication among the 
individual Access Point Management Applications within a neighborhood over the wired Internet backbone.
We have implemented a prototype of ResFi and studied its performance in our testbed.
As a showcase we have implemented various RRM applications among others a distributed channel assignment algorithm using ResFi.
ResFi is provided to the community as open source.

For more details please refer to our Paper:
<http://www.tkn.tu-berlin.de/fileadmin/fg112/Papers/2015/Zehl15resfi.pdf>

## 1. Installation

### 1.1. On real hardware

We tested ResFi on the following platforms:
* Linux (Ubuntu) on x86 hardware (Intel) with IEEE 802.11 wireless devices (Atheros (ATH9K))

Just execute:
```
$ sudo apt-get update ; sudo apt-get install git ; git clone https://github.com/resfi/resfi.git ; cd resfi ; chmod +x install_deps.sh ; ./install_deps.sh
```

Build hostapd and iw:

```
$ cd hostapd-20131120/hostapd/; make; cd ../../
```
```
$ cd iw-4.3; make; cd ..
```

### 1.2. Emulation in Mininet

Emulation is tested Ubuntu 12.10 with Mininet 2.2.0
To install Mininet follow the information on http://mininet.org/download/ or simply do: sudo apt-get install mininet
No more prerequisites are required. Mininet must be run under root privileges.

## 2. Start-up

### 2.1. On real hardware

When using real hardware, please ensure that the connector module within the framework configuration file (framework/config.py) is set to CONNECTOR = "linux"
Further, adjust the name of the wired interface used for Internet connection (default eth0) in the config file using your favourite editor e.g. vim framework/config.py.


Afterwards execute:
```
$ ./start_resfi.sh phyX
```
while phyX has to be replaced by the corresponding physical interface of the wireless adapter. 
The hostapd configuration file which is used can be found in the subfolder hostapd-20131120/hostapd/hostapd-ch40.conf and can be adjusted to the needed purpose.

### 2.2. Emulation in Mininet

When using Mininet emulation, please ensure that the connector module within the framework configuration file (framework/config.py) is set to CONNECTOR = "mininet"
Afterwards execute:
```
$ cd framework/mininet; sudo python mn_driver.py
```
The additional --help command will provide more configuration possibilities.
e.g.

    usage: sudo python mn_driver.py [-h] [-r RUNTIME] [-s SEED] [-t TOPO] [-n NODES] [-c CLI]
    Commandline options:
      -h, --help                      show help message and exit
      -r RUNTIME, --runtime RUNTIME   Emulation runtime
      -s SEED, --seed SEED            Seed
      -t TOPO, --topo TOPO            Choose topology: star, tree
      -n NODES, --nodes NODES         Maximum number of nodes. 
      -c CLI, --cli CLI               (1) Open Mininet CLI for manual simulation, 
                                      afterwards type xterm apX for node access.
                                      (0) executes resfi_loader.py on every node 
                                      after the mininet topology has been loaded (default).



## 3. How to write an own ResFi application

* all ResFi apps are placed under apps/ folder
* at start-up all apps are automatically loaded and started
* all ResFi apps have to derive from class AbstractResFiApp and implement the functions run() and the callback functions for new neighbor found, neighbor left and for receiving messages from neighboring ResFi APs.

The following illustrates an example of a ResFi app:
```
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

```

## 9. Contact
* Sven Zehl, TU-Berlin, zehl@tkn
* Anatolij Zubow, TU-Berlin, zubow@tkn
* Michael Döring, TU-Berlin, doering@tkn
* tkn = tkn.tu-berlin.de
