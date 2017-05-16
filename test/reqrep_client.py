import zmq
import sys
import json

port = "9999"
if len(sys.argv) > 1:
    port =  sys.argv[1]
    int(port)

if len(sys.argv) > 2:
    port1 =  sys.argv[2]
    int(port1)

context = zmq.Context()
print "Connecting to server..."
socket = context.socket(zmq.REQ)
socket.connect ("tcp://localhost:%s" % port)
if len(sys.argv) > 2:
    socket.connect ("tcp://localhost:%s" % port1)

#  Do 10 requests, waiting each time for a response
#print "Sending request ", request,"..."
socket.send ("Hello")
#  Get the reply.
message = socket.recv()
#print "Received reply ", request, "[", message, "]"
aps = json.loads(message)
#print "jsonloads: "+str(aps)

load = {}
freq = {}

for ap in aps:
    for sta in aps[ap]:
        if sta == "activeStas":# and len(aps[ap][sta]) > 0:
            print "AP: "+str(ap) + " STAs: " +str(aps[ap][sta]) + " Load: "+str(len(aps[ap][sta]))
            load[str(ap)] = len(aps[ap][sta])   
            freq[str(ap)] = aps[ap]['freq']

print str(load)
print str(freq)
